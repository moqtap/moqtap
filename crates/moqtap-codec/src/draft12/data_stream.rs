//! Draft-12 data stream header encoding and decoding.
//!
//! Changes from draft-11:
//! - Subgroup stream type IDs shift from 0x08-0x0D to 0x10-0x15
//! - Datagram types (separate namespace): 0x00-0x05
//! - Fetch type: same as draft-11 (0x05)

use super::types::ObjectStatus;
use crate::error::CodecError;
use crate::object_properties::{parse_object_properties, ObjectProperty, PropertyValue};
use crate::types::read_bytes;
use crate::varint::VarInt;
use crate::version::DraftVersion;
use bytes::{Buf, BufMut};

/// Stream type IDs for draft-12 data streams.
///
/// # Draft-12 contradicts itself about where the subgroup types sit
///
/// Three places in this draft name the SUBGROUP_HEADER Type range, and they do
/// not agree. Two of them carry draft-11's answer:
///
///   - Section 9, Table 10, the table of unidirectional stream types, whose
///     SUBGROUP_HEADER row reads 0x08-0x0D.
///   - Section 9.4.2, Figure 35, the header's own layout:
///     `Type (i) = 0x8..0xD`.
///
/// The third does not. Section 9.4.2 says "There are 12 defined Type values for
/// SUBGROUP_HEADER" and Table 13, immediately under that figure, lists them:
/// 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x18, 0x19, 0x1A, 0x1B, 0x1C and 0x1D.
///
/// **This enum implements Table 13**, so a stream opening with 0x08 through
/// 0x0D is [`CodecError::UnknownStreamType`] and closes the session.
///
/// Table 13 is the surviving half, for the same reason and by the same
/// mechanism as the datagram-status contradiction documented on
/// [`DatagramType`] — a code-point update that missed a spot:
///
///   - The range 0x08-0x0D holds six values, and this draft defines twelve
///     types. Draft-11 Section 9.4.2 Table 11 lists exactly six, at 0x08
///     through 0x0D, and the twelve here are those six crossed with the End Of
///     Group bit draft-12 added — its own change log says so: "Use bits in
///     SUBGROUP_HEADER and DATAGRAM* types to compress subgroup ID and
///     extensions". So 0x08-0x0D and `0x8..0xD` are draft-11's range left
///     behind, and they cannot hold what this draft defines.
///   - Table 13 is the only one of the three that says what each value *means*.
///     The other two give a range and nothing else, so following either would
///     leave every framing decision — whether a Subgroup ID field is on the
///     wire, whether objects carry extensions, whether the stream ends the
///     group — with nothing to read it from.
///   - Draft-14 keeps Table 13 unchanged and corrects the other two to match:
///     its Table 10 reads "0x10-0x1D" and its Figure reads
///     `Type (i) = 0x10..0x1D`. That is the disagreement being resolved in
///     favour of Table 13 by the working group, one draft later.
///
/// Draft-13 repeats all three halves unchanged, and carries the same note.
///
/// The cost of being wrong is asymmetric and points the same way. Accepting
/// 0x08-0x0D as well would mean parsing a stream under framing no table
/// assigns it, which is the failure this codebase refuses elsewhere — an
/// out-of-range Type aliased onto a valid one produces objects with plausible,
/// wrong contents. Refusing them closes a session with a peer that followed the
/// stale half of its own draft, which is visible, reportable, and what
/// draft-14 says the peer should not have done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StreamType {
    /// Fetch response stream (0x05).
    Fetch = 0x05,
    /// Subgroup: subgroup_id=0, no extensions (0x10).
    SubgroupZero = 0x10,
    /// Subgroup: subgroup_id=0, with extensions (0x11).
    SubgroupZeroExt = 0x11,
    /// Subgroup: subgroup_id=first object ID, no extensions (0x12).
    SubgroupFirstObj = 0x12,
    /// Subgroup: subgroup_id=first object ID, with extensions (0x13).
    SubgroupFirstObjExt = 0x13,
    /// Subgroup: explicit subgroup_id, no extensions (0x14).
    SubgroupExplicit = 0x14,
    /// Subgroup: explicit subgroup_id, with extensions (0x15).
    SubgroupExplicitExt = 0x15,
    /// Subgroup: subgroup_id=0, contains end of group, no extensions (0x18).
    SubgroupZeroEog = 0x18,
    /// Subgroup: subgroup_id=0, contains end of group, with extensions (0x19).
    SubgroupZeroEogExt = 0x19,
    /// Subgroup: subgroup_id=first object ID, contains end of group, no extensions (0x1A).
    SubgroupFirstObjEog = 0x1A,
    /// Subgroup: subgroup_id=first object ID, contains end of group, with extensions (0x1B).
    SubgroupFirstObjEogExt = 0x1B,
    /// Subgroup: explicit subgroup_id, contains end of group, no extensions (0x1C).
    SubgroupExplicitEog = 0x1C,
    /// Subgroup: explicit subgroup_id, contains end of group, with extensions (0x1D).
    SubgroupExplicitEogExt = 0x1D,
}

/// Hold an object to the rule that a non-existent object carries no extensions.
///
/// Section 9.2.1.2: "Any Object may have extension headers except those with
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

    /// True if this subgroup stream type indicates the stream contains the end of its group.
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

    /// True if this subgroup stream type puts an explicit Subgroup ID on the
    /// wire.
    ///
    /// The Subgroup ID Field Present column of the SUBGROUP_HEADER type table
    /// in Section 9.4.2. The other two columns of that row say what the
    /// Subgroup ID *is* where the field is absent — zero, or the first
    /// Object's ID — so this is only about the field, never about the value.
    pub fn writes_subgroup_id(&self) -> bool {
        matches!(
            self,
            StreamType::SubgroupExplicit
                | StreamType::SubgroupExplicitExt
                | StreamType::SubgroupExplicitEog
                | StreamType::SubgroupExplicitEogExt
        )
    }
}

/// Datagram wire types (separate namespace from QUIC stream types).
///
/// The two namespaces overlap in draft-12 and cannot share one enum: 0x05 is
/// FETCH_HEADER among stream types and OBJECT_DATAGRAM_STATUS with extensions
/// among datagram types.
///
/// Draft-12 contradicts itself about where the status types sit. Its table of
/// datagram types gives OBJECT_DATAGRAM 0x00 through 0x03 and
/// OBJECT_DATAGRAM_STATUS 0x04 through 0x05, and the four OBJECT_DATAGRAM
/// values are spelled out one by one as the End Of Group bit crossed with the
/// Extensions bit — the End Of Group bit being what this draft added. But the
/// sentence under the OBJECT_DATAGRAM_STATUS figure still reads "the set of
/// values from 0x02 to 0x03", which is draft-11's range from before the bit
/// existed and cannot be squared with the table above it. Draft-13 repeats both
/// halves unchanged; draft-14 keeps the table's answer and records the sentence
/// as a missed code-point update. The table is therefore the surviving half and
/// the values below follow it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DatagramType {
    /// Object datagram, no extensions (0x00).
    Datagram = 0x00,
    /// Object datagram, with extensions (0x01).
    DatagramExt = 0x01,
    /// Object datagram carrying the end of its group, no extensions (0x02).
    DatagramEog = 0x02,
    /// Object datagram carrying the end of its group, with extensions (0x03).
    DatagramEogExt = 0x03,
    /// Object datagram status, no extensions (0x04).
    DatagramStatus = 0x04,
    /// Object datagram status, with extensions (0x05).
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

/// Which failure a leading unidirectional stream type that is not the one a
/// reader wants is.
///
/// Section 9: "An endpoint that receives an unknown stream or datagram type
/// MUST close the session." One sentence, two tables, and on this draft the two
/// tables collide: 0x05 is FETCH_HEADER in the stream table and
/// OBJECT_DATAGRAM_STATUS with extensions in the datagram table. Which table
/// was consulted is therefore part of the answer, not a detail, and it is why
/// [`CodecError::UnknownStreamType`] and [`CodecError::UnknownDatagramType`]
/// are separate variants rather than one.
///
/// The stream table assigns 0x05 and the range 0x10 to 0x1D. Everything outside
/// them is unknown at the head of a stream, and the session ends.
fn stream_type_error(raw: u64) -> CodecError {
    if StreamType::from_id(raw).is_some() {
        CodecError::InvalidField
    } else {
        CodecError::UnknownStreamType(raw)
    }
}

/// Which failure a leading datagram type that is not one a reader wants is.
///
/// The datagram half of the sentence quoted on `stream_type_error`, read
/// against the other table: 0x00 to 0x05 are what it assigns, and everything
/// else arriving as a datagram is unknown.
///
/// Answered from [`DatagramType`] alone, never from [`StreamType`]. A value in
/// both tables means one thing as a datagram and another as a stream, and
/// consulting the wrong one turns an assigned datagram type into an unknown one
/// or the reverse.
fn datagram_type_error(raw: u64) -> CodecError {
    if DatagramType::from_id(raw).is_some() {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupHeader {
    pub stream_type: StreamType,
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub subgroup_id: VarInt,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHeader {
    pub object_id: VarInt,
    pub extension_headers_length: VarInt,
    pub extensions: Vec<u8>,
    pub payload_length: VarInt,
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
    /// Object Payload Length is zero, and Section 9.2.1.1 says "Any object
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
        check_extensions_against_status(object_status, &extensions)?;
        Ok(Self { object_id, extension_headers_length, extensions, payload_length, object_status })
    }
}

// ============================================================
// Prior Group ID Gap
// ============================================================

/// Prior Group ID Gap, Extension Header Type 0x40 (draft-12 Section 10.1).
pub const PRIOR_GROUP_ID_GAP: u64 = 0x40;

/// The Prior Group ID Gap values one Object carries.
///
/// draft-12 Section 10.1: "A track with a Group that contains more than one
/// Object with different values for Prior Group ID Gap or has a Prior Group ID
/// Gap larger than the Group ID is considered malformed." Malformed Tracks are
/// draft-12 Section 2.5. This draft does not limit an Object to one instance,
/// so every value is kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PriorGaps {
    /// Each Prior Group ID Gap, in wire order.
    pub group: Vec<u64>,
}

impl PriorGaps {
    /// Read the gaps from an Object's parsed extension headers, refusing one
    /// larger than `group_id` with [`CodecError::MalformedTrack`].
    pub fn from_properties(
        properties: &[ObjectProperty<'_>],
        group_id: u64,
    ) -> Result<Self, CodecError> {
        let group: Vec<u64> = properties
            .iter()
            .filter_map(|property| match (property.property_type, &property.value) {
                (PRIOR_GROUP_ID_GAP, PropertyValue::Varint(value)) => Some(*value),
                _ => None,
            })
            .collect();
        if let Some(gap) = group.iter().copied().find(|&gap| gap > group_id) {
            return Err(CodecError::MalformedTrack {
                detail: format!("Prior Group ID Gap {gap} is larger than Group ID {group_id}"),
            });
        }
        Ok(Self { group })
    }

    /// [`Self::from_properties`] on an extension block, refusing a block that
    /// does not parse as [`crate::object_properties::parse_object_properties`]
    /// does.
    pub fn from_extensions(extensions: &[u8], group_id: u64) -> Result<Self, CodecError> {
        let properties = parse_object_properties(DraftVersion::Draft12, extensions)?;
        Self::from_properties(&properties, group_id)
    }
}

/// The Prior Group ID Gap values the Objects of one subgroup stream carried.
///
/// A subgroup stream carries one Group, so its Objects are where "a Group that
/// contains more than one Object with different values for Prior Group ID Gap"
/// (draft-12 Section 10.1) shows on one stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupGaps {
    group_id: u64,
    seen: Vec<u64>,
}

impl SubgroupGaps {
    /// Track the Objects of the stream `header` opens.
    pub fn new(header: &SubgroupHeader) -> Self {
        Self { group_id: header.group_id.into_inner(), seen: Vec::new() }
    }

    /// Check the next Object on this stream, refusing with
    /// [`CodecError::MalformedTrack`] a gap larger than the Group ID or one
    /// that differs from a gap an earlier Object on the stream carried. The
    /// values one Object carries are not compared with each other. Records the
    /// Object only when it passes.
    pub fn check(&mut self, object: &ObjectHeader) -> Result<PriorGaps, CodecError> {
        let gaps = PriorGaps::from_extensions(&object.extensions, self.group_id)?;
        if gaps.group.iter().any(|gap| self.seen.iter().any(|seen| seen != gap)) {
            return Err(CodecError::MalformedTrack {
                detail: format!(
                    "two Objects in Group {} carry different Prior Group ID Gap values",
                    self.group_id
                ),
            });
        }
        for &gap in &gaps.group {
            if !self.seen.contains(&gap) {
                self.seen.push(gap);
            }
        }
        Ok(gaps)
    }
}

// ============================================================
// Datagram (types 0x00 through 0x03)
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramHeader {
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub object_id: VarInt,
    pub publisher_priority: u8,
    pub extension_headers_length: VarInt,
    pub extensions: Vec<u8>,
    /// Whether this object is the last one in its group.
    ///
    /// Draft-12 added this flag and put it in the datagram type rather than in
    /// the header body, so it is not written or read by the methods below;
    /// [`DatagramType::is_end_of_group`] is where it lives on the wire.
    pub end_of_group: bool,
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
    /// than a check left out. This is the OBJECT_DATAGRAM of Section 9.3.1,
    /// whose layout carries no Object Status field at all; a datagram that
    /// states a status is the separate OBJECT_DATAGRAM_STATUS message, modelled
    /// here as [`DatagramStatusHeader`]. So there is no status for
    /// [`Self::encode`] to drop, and nothing for Section 9.2.1.1's "Any object
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
    /// on receipt, and one that announces none has nowhere to put them. The end
    /// of group bit has no home in the body at all, so it comes from the header
    /// flag and goes nowhere else.
    pub fn datagram_type(&self) -> DatagramType {
        match self {
            Self::Payload(header) => match (header.end_of_group, header.extensions.is_empty()) {
                (false, true) => DatagramType::Datagram,
                (false, false) => DatagramType::DatagramExt,
                (true, true) => DatagramType::DatagramEog,
                (true, false) => DatagramType::DatagramEogExt,
            },
            Self::Status(header) => {
                if header.extensions.is_empty() {
                    DatagramType::DatagramStatus
                } else {
                    DatagramType::DatagramStatusExt
                }
            }
        }
    }

    /// Decode a datagram from its first byte, type field included.
    ///
    /// Errors with [`CodecError::UnknownDatagramType`] when the datagram table
    /// does not assign the leading type, which this draft answers with a close.
    /// `datagram_type_error` settles it against that table alone — 0x05 is
    /// assigned in both tables here and means different things in each.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let raw = VarInt::decode(buf)?.into_inner();
        let datagram_type = DatagramType::from_id(raw).ok_or_else(|| datagram_type_error(raw))?;
        let has_extensions = datagram_type.has_extensions();
        if datagram_type.is_status() {
            return Ok(Self::Status(DatagramStatusHeader::decode_with_extensions(
                has_extensions,
                buf,
            )?));
        }
        let mut header = DatagramHeader::decode_with_extensions(has_extensions, buf)?;
        header.end_of_group = datagram_type.is_end_of_group();
        Ok(Self::Payload(header))
    }

    /// Decode one whole datagram: [`Self::decode`], then the payload that runs
    /// to the end of `buf`, which must hold exactly one transport datagram.
    ///
    /// Unlike [`Self::decode`], this refuses an extension block that does not
    /// parse, as [`crate::object_properties::parse_object_properties`] does,
    /// and, with [`CodecError::MalformedTrack`], a Prior Group ID Gap larger
    /// than the datagram's Group ID, through [`PriorGaps::from_extensions`].
    /// draft-12 Section 9.3 carries the Group ID and the extension headers in
    /// one datagram, so this half of the draft-12 Section 10.1 rule shows in it.
    ///
    /// It also refuses bytes after a status datagram's Object Status, with
    /// [`CodecError::PayloadNotPermitted`]. draft-12 Section 9.3.2: "An
    /// OBJECT_DATAGRAM_STATUS is similar to OBJECT_DATAGRAM except it conveys
    /// an Object Status and has no payload."
    pub fn decode_object(buf: &mut impl Buf) -> Result<(Self, Vec<u8>), CodecError> {
        let datagram = Self::decode(buf)?;
        let (group_id, extensions) = match &datagram {
            Self::Payload(header) => (header.group_id.into_inner(), &header.extensions),
            Self::Status(header) => (header.group_id.into_inner(), &header.extensions),
        };
        PriorGaps::from_extensions(extensions, group_id)?;
        let payload = read_bytes(buf, buf.remaining())?;
        if let Self::Status(header) = &datagram {
            if !payload.is_empty() {
                return Err(CodecError::PayloadNotPermitted {
                    status: header.object_status.as_u64(),
                    len: payload.len(),
                    detail: "its type states a status in place of a payload",
                });
            }
        }
        Ok((datagram, payload))
    }

    /// Encode the datagram, type field included.
    pub fn encode(&self, buf: &mut impl BufMut) {
        let datagram_type = self.datagram_type();
        let has_extensions = datagram_type.has_extensions();
        VarInt::from_usize(datagram_type as usize).encode(buf);
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
        let datagram_type = self.datagram_type();
        let has_extensions = datagram_type.has_extensions();
        match self {
            Self::Payload(header) => header.encode_with_extensions(has_extensions, &mut body),
            Self::Status(header) => {
                check_extensions_against_status(header.object_status, &header.extensions)?;
                header.encode_with_extensions(has_extensions, &mut body);
            }
        }
        VarInt::from_usize(datagram_type as usize).encode(buf);
        buf.put_slice(&body);
        Ok(())
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

    pub fn encode(&self, buf: &mut impl BufMut) {
        self.request_id.encode(buf);
    }

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
    /// Object Payload Length is zero, and Section 9.2.1.1 says "Any object
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A payload datagram for track 1, group 0, object 7, priority 128, with
    /// no extension block — the shape [`DatagramHeader::encode`] writes.
    fn payload_datagram() -> DatagramHeader {
        DatagramHeader {
            track_alias: VarInt::from_usize(1),
            group_id: VarInt::from_usize(0),
            object_id: VarInt::from_usize(7),
            publisher_priority: 128,
            extension_headers_length: VarInt::from_usize(0),
            extensions: Vec::new(),
            end_of_group: false,
        }
    }

    /// The same datagram on the message that does carry a status.
    fn status_datagram(status: ObjectStatus) -> DatagramStatusHeader {
        DatagramStatusHeader {
            track_alias: VarInt::from_usize(1),
            group_id: VarInt::from_usize(0),
            object_id: VarInt::from_usize(7),
            publisher_priority: 128,
            extension_headers_length: VarInt::from_usize(0),
            extensions: Vec::new(),
            object_status: status,
        }
    }

    /// Draft-12's payload datagram has no status for the encoder to drop, and
    /// so nothing for the fallible encode to refuse.
    ///
    /// [`DatagramHeader`] is the OBJECT_DATAGRAM of Section 9.3.1, whose layout
    /// carries no Object Status field at all. A datagram that states a status
    /// is the separate OBJECT_DATAGRAM_STATUS message of Section 9.3.2, modelled
    /// here as [`DatagramStatusHeader`]. The refusal drafts 07, 08 and 14-19
    /// need on this path therefore has nothing to bite on, and this gate holds
    /// [`DatagramHeader::encode_checked`] to writing exactly what
    /// [`DatagramHeader::encode`] writes and never refusing — the alternative
    /// being a codec that answers `Err` for a datagram every draft-12 publisher
    /// is entitled to send.
    ///
    /// The second half is what makes the first half safe rather than merely
    /// permissive. Every status draft-12 assigns travels intact on the message
    /// that can express one, so leaving the payload datagram unchecked loses
    /// nothing; if a status could ride this header, the check being skipped
    /// here would be the check drafts 07 and 18 need.
    #[test]
    fn a_payload_datagram_has_no_status_to_refuse() {
        let header = payload_datagram();

        let mut checked = Vec::new();
        header.encode_checked(&mut checked).unwrap_or_else(|e| {
            panic!("draft-12's payload datagram has no status to refuse: {e:?}")
        });

        let mut plain = Vec::new();
        header.encode(&mut plain);
        assert_eq!(checked, plain, "the fallible encode must write exactly what `encode` writes");

        let decoded = DatagramHeader::decode(&mut &checked[..])
            .expect("the bytes encode_checked wrote must parse back");
        assert_eq!(decoded, header, "the payload datagram did not survive its own encoding");

        for &status in ObjectStatus::ALL {
            let mut buf = Vec::new();
            status_datagram(status).encode(&mut buf);
            let decoded = DatagramStatusHeader::decode(&mut &buf[..])
                .unwrap_or_else(|e| panic!("the status datagram for {status:?} must parse: {e:?}"));
            assert_eq!(
                decoded.object_status, status,
                "{status:?} must survive on the message that carries a status"
            );
        }
    }
}

#[cfg(test)]
mod prior_gap_tests {
    use super::*;

    fn header(group: usize) -> SubgroupHeader {
        SubgroupHeader {
            stream_type: StreamType::SubgroupZeroExt,
            track_alias: VarInt::from_usize(1),
            group_id: VarInt::from_usize(group),
            subgroup_id: VarInt::from_usize(0),
            publisher_priority: 0x80,
        }
    }

    fn gaps_block(gaps: &[usize]) -> Vec<u8> {
        let mut block = Vec::new();
        for &gap in gaps {
            VarInt::from_usize(PRIOR_GROUP_ID_GAP as usize).encode(&mut block);
            VarInt::from_usize(gap).encode(&mut block);
        }
        block
    }

    fn object(id: usize, gaps: &[usize]) -> ObjectHeader {
        let extensions = gaps_block(gaps);
        ObjectHeader {
            object_id: VarInt::from_usize(id),
            extension_headers_length: VarInt::from_usize(extensions.len()),
            extensions,
            payload_length: VarInt::from_usize(1),
            object_status: ObjectStatus::Normal,
        }
    }

    fn is_malformed_track<T>(result: Result<T, CodecError>) -> bool {
        matches!(result, Err(CodecError::MalformedTrack { .. }))
    }

    #[test]
    fn gap_larger_than_the_group_id_is_refused() {
        assert!(is_malformed_track(SubgroupGaps::new(&header(1)).check(&object(0, &[2]))));
        let gaps = SubgroupGaps::new(&header(2)).check(&object(0, &[2])).unwrap();
        assert_eq!(gaps.group, vec![2]);
    }

    #[test]
    fn objects_with_different_gaps_are_refused() {
        let mut gaps = SubgroupGaps::new(&header(5));
        gaps.check(&object(0, &[2])).unwrap();
        gaps.check(&object(1, &[])).unwrap();
        gaps.check(&object(2, &[2])).unwrap();
        assert!(is_malformed_track(gaps.check(&object(3, &[3]))));
    }

    #[test]
    fn values_within_one_object_are_not_compared() {
        let mut gaps = SubgroupGaps::new(&header(5));
        assert_eq!(gaps.check(&object(0, &[2, 3])).unwrap().group, vec![2, 3]);
        assert!(is_malformed_track(gaps.check(&object(1, &[2]))));
    }

    #[test]
    fn a_refused_object_is_not_recorded() {
        let mut gaps = SubgroupGaps::new(&header(5));
        assert!(is_malformed_track(gaps.check(&object(0, &[6]))));
        gaps.check(&object(1, &[3])).unwrap();
    }

    fn datagram(group: usize, gaps: &[usize]) -> Vec<u8> {
        let extensions = gaps_block(gaps);
        let mut bytes = Vec::new();
        Datagram::Payload(DatagramHeader {
            track_alias: VarInt::from_usize(1),
            group_id: VarInt::from_usize(group),
            object_id: VarInt::from_usize(0),
            publisher_priority: 0x80,
            extension_headers_length: VarInt::from_usize(extensions.len()),
            extensions,
            end_of_group: false,
        })
        .encode(&mut bytes);
        bytes.push(0xAA);
        bytes
    }

    #[test]
    fn decode_object_refuses_a_gap_larger_than_the_datagram_group_id() {
        let wire = datagram(1, &[2]);
        assert!(is_malformed_track(Datagram::decode_object(&mut &wire[..])));
        assert!(Datagram::decode(&mut &wire[..]).is_ok());
        let wire = datagram(2, &[2]);
        let (decoded, payload) = Datagram::decode_object(&mut &wire[..]).unwrap();
        assert_eq!(decoded.datagram_type(), DatagramType::DatagramExt);
        assert_eq!(payload, vec![0xAA]);
    }

    #[test]
    fn decode_object_refuses_a_payload_after_a_status_datagram() {
        let mut wire = Vec::new();
        Datagram::Status(DatagramStatusHeader {
            track_alias: VarInt::from_usize(1),
            group_id: VarInt::from_usize(0),
            object_id: VarInt::from_usize(0),
            publisher_priority: 0x80,
            extension_headers_length: VarInt::from_usize(0),
            extensions: Vec::new(),
            object_status: ObjectStatus::Normal,
        })
        .encode(&mut wire);
        let (_, payload) = Datagram::decode_object(&mut &wire[..]).unwrap();
        assert!(payload.is_empty());
        wire.push(0xAA);
        assert!(matches!(
            Datagram::decode_object(&mut &wire[..]),
            Err(CodecError::PayloadNotPermitted { len: 1, .. })
        ));
    }
}

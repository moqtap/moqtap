//! Draft-14 data streams: subgroup streams, fetch streams, datagrams.
//!
//! Draft-14 carries object data in three wire shapes:
//!
//! * **Subgroup stream**: starts with a Type byte `0x10..=0x1D`
//!   whose bit-flags determine whether a Subgroup ID field is present,
//!   whether the subgroup ID is zero or the first Object ID, whether
//!   extension headers are present, and whether the stream ends at a
//!   group boundary. Object IDs are delta-encoded relative to the
//!   previous Object ID in the same stream.
//!
//! * **Fetch stream**: Type `0x05`, Request ID, then a sequence
//!   of self-describing objects until FIN.
//!
//! * **Datagram**: Type byte `0x00..=0x07` or `0x20..=0x21`
//!   with bit-flags for End of Group, Extensions Present, Object ID
//!   Present, and Status vs Payload.

use bytes::{Buf, BufMut};

use super::types::ObjectStatus;
use crate::error::CodecError;
use crate::varint::VarInt;

/// Advance `buf` past `len` bytes without copying them.
fn skip(buf: &mut impl Buf, len: u64) -> Result<(), CodecError> {
    let len = usize::try_from(len).map_err(|_| CodecError::UnexpectedEnd)?;
    if buf.remaining() < len {
        return Err(CodecError::UnexpectedEnd);
    }
    buf.advance(len);
    Ok(())
}

/// Hold an object to the rule binding extension headers to Object Status.
///
/// Draft-14 Section 10.2.1.2: "Any Object may have extension headers except
/// those with Object Status 'Object Does Not Exist'. If an endpoint receives a
/// non-existent Object containing extension headers it MUST close the session
/// with a PROTOCOL_VIOLATION."
///
/// The rule names one status and no others, so extensions beside End of Group
/// or End of Track stay legal and are left alone here. The reasoning behind the
/// exception is that an object nobody has cannot carry metadata about itself:
/// a relay that forwards the extensions of a non-existent object is inventing
/// provenance for something that was never published.
///
/// All three carriers reach this, in both directions — subgroup streams, fetch
/// streams and status datagrams each pair a status with an extension block.
///
/// Reported under [`CodecError::ExtensionsOnNonExistentObject`], which is this
/// rule and nothing else. It was [`CodecError::InvalidField`] until now, shared
/// with a dozen unrelated malformations the draft does not answer with a close,
/// which left a caller unable to act on the sentence above.
fn check_extensions_against_status(
    status: Option<u64>,
    extension_headers_len: u64,
) -> Result<(), CodecError> {
    if status == Some(ObjectStatus::ObjectDoesNotExist.as_u64()) && extension_headers_len != 0 {
        // The length is reported as it appeared on the wire; saturating rather
        // than truncating means a declared length above `usize::MAX` — which
        // cannot have been read, but can have been declared — is never reported
        // as some smaller, plausible number.
        return Err(CodecError::ExtensionsOnNonExistentObject(
            usize::try_from(extension_headers_len).unwrap_or(usize::MAX),
        ));
    }
    Ok(())
}

// ============================================================
// Subgroup stream (Type 0x10..=0x1D)
// ============================================================

/// Subgroup stream type byte.
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
    /// that it is one of the 12 defined values. `0x16` and `0x17` fall
    /// inside the `0x10..=0x1D` range but are not defined, so a range
    /// check alone is not enough.
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

/// Subgroup stream header.
///
/// Wire order: type byte, Track Alias, Group ID, Subgroup ID (only for
/// stream types that carry one), Publisher Priority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupHeader {
    /// Type byte identifying the flag set for this stream.
    pub stream_type: SubgroupStreamType,
    /// Track alias.
    pub track_alias: VarInt,
    /// Group ID.
    pub group_id: VarInt,
    /// Explicit Subgroup ID — present only when the stream type sets
    /// `Subgroup ID Field Present = Yes`. For types where the subgroup
    /// ID is implicit (0 or the first Object ID), the effective
    /// subgroup ID is resolved on the receive side by the reader.
    pub subgroup_id: Option<VarInt>,
    /// Publisher priority.
    pub publisher_priority: u8,
}

impl SubgroupHeader {
    /// Encode the header including the leading stream type byte.
    ///
    /// Driven by `stream_type`, and silent about a `subgroup_id` that
    /// disagrees with it in either direction: a `None` under a type whose
    /// Subgroup ID Field Present column reads Yes is written as zero, which
    /// names a different subgroup rather than no subgroup, and a `Some` under
    /// a type whose column reads No is dropped. Both write a well-formed
    /// stream describing something other than what the caller built.
    /// [`Self::encode_checked`] refuses that shape instead.
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

    /// Encode, refusing a header whose Subgroup ID disagrees with its own type
    /// byte.
    ///
    /// Section 10.4.2 gives the SUBGROUP_HEADER type table a Subgroup ID Field
    /// Present column, and that column - not the value in hand - decides
    /// whether the field is on the wire. [`Self::decode`] therefore only ever
    /// produces a header where the two agree, so this refuses exactly the
    /// shapes a caller assembled by hand: an absent ID under a type that
    /// carries one, and a present ID under a type that does not.
    ///
    /// Nothing about the *value* is refused. Zero is a legal Subgroup ID, so a
    /// `Some(0)` under a type that carries the field is written as the caller
    /// asked.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] if the presence of `subgroup_id` does not
    /// match what `stream_type` puts on the wire.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        if self.stream_type.has_subgroup_id_field() != self.subgroup_id.is_some() {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
    }

    /// Decode a subgroup header (leading type byte + remaining fields).
    ///
    /// Errors with [`CodecError::UnknownStreamType`] when the stream table does
    /// not assign the leading type, which this draft answers with a close, and
    /// with [`CodecError::InvalidField`] for `0x05`, which it assigns to a
    /// fetch stream. `stream_type_error` draws that line.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_val = VarInt::decode(buf)?.into_inner();
        if type_val > 0xFF {
            return Err(stream_type_error(type_val));
        }
        let stream_type = SubgroupStreamType::from_u8(type_val as u8)
            .ok_or_else(|| stream_type_error(type_val))?;
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
    /// The content is a sequence of Key-Value-Pairs but is
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

/// The framing of one subgroup object, without its payload.
///
/// Produced by [`SubgroupObjectReader::read_object_meta`] for callers that
/// forward an object's bytes verbatim and never inspect the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubgroupObjectMeta {
    /// Resolved Object ID (delta decoded to an absolute value).
    pub object_id: u64,
    /// Byte length of the extension-header block's contents, excluding its
    /// length prefix.
    pub extension_headers_len: u64,
    /// Declared payload length. Zero when `status` is `Some`.
    pub payload_length: u64,
    /// Object Status wire code, present only when the payload is empty.
    pub status: Option<u64>,
    /// Total bytes this object occupies on the wire, prefix fields included.
    pub wire_len: u64,
}

/// Whether an object carrying a given status may hold a non-empty payload.
///
/// Section 10.2.1.1 states the rule in one sentence — "Any object with a
/// status code other than zero MUST have an empty payload" — so on this draft
/// the answer falls out of the code being zero or not, and every status but
/// [`ObjectStatus::Normal`] forbids a payload.
///
/// It is worth a type all the same, because that arithmetic is not something a
/// consumer can safely perform on a raw wire code. A code this draft does not
/// assign is not *non-zero, and therefore forbidden*: it is a code with no
/// meaning at all, and no payload rule attaches to it. Handing back a
/// `PayloadPermission` keeps the two apart, and lets a caller ask the question
/// without restating the rule — or, worse, restating it slightly differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadPermission {
    /// The status permits a payload but does not require one: a zero-length
    /// object with such a status is well formed, and this draft's encodings
    /// have a way to spell it.
    Permitted,
    /// An object with such a status has an empty payload, and one carrying
    /// bytes is malformed.
    Forbidden,
}

impl PayloadPermission {
    /// The permission this draft gives objects carrying `status`.
    ///
    /// Written as a match over every assigned status rather than as a test for
    /// zero, so that a status added to [`ObjectStatus`] later cannot quietly
    /// inherit *not Normal, therefore forbidden* — it stops the crate
    /// compiling until its own answer is written down.
    pub fn for_status(status: ObjectStatus) -> Self {
        match status {
            ObjectStatus::Normal => PayloadPermission::Permitted,
            ObjectStatus::ObjectDoesNotExist => PayloadPermission::Forbidden,
            ObjectStatus::EndOfGroup => PayloadPermission::Forbidden,
            ObjectStatus::EndOfTrack => PayloadPermission::Forbidden,
        }
    }

    /// `true` for [`PayloadPermission::Permitted`].
    ///
    /// The permission answers on its own, with no payload length in hand,
    /// which is the point of asking the status rather than the framing.
    pub fn permits(self) -> bool {
        matches!(self, PayloadPermission::Permitted)
    }
}

impl SubgroupObject {
    /// The status this object resolves to.
    ///
    /// The wire carries a status field only on an empty object, so an object
    /// holding bytes is [`ObjectStatus::Normal`] whatever `status` says.
    pub fn status(&self) -> ObjectStatus {
        if self.payload.is_empty() {
            self.status.unwrap_or(ObjectStatus::Normal)
        } else {
            ObjectStatus::Normal
        }
    }

    /// Whether this object's status permits it a non-empty payload.
    ///
    /// Answered from the status alone. `payload` is not consulted: on a status
    /// that permits a payload it says only whether this particular object took
    /// the offer, and on one that forbids a payload a non-empty payload is the
    /// malformation this reports, not evidence about the rule.
    pub fn permits_payload(&self) -> bool {
        PayloadPermission::for_status(self.status()).permits()
    }
}

impl SubgroupObjectMeta {
    /// Whether this object's status permits it a non-empty payload.
    ///
    /// The same question [`SubgroupObject::permits_payload`] answers, from the
    /// declared length and the wire code rather than from the bytes. A relay
    /// that forwards an object verbatim reads it through
    /// [`SubgroupObjectReader::read_object_meta`] and never copies the payload,
    /// so asking this must not require having it.
    ///
    /// An absent status answers [`PayloadPermission::Permitted`] rather than
    /// `None`. A meta has no status only when its payload length is non-zero,
    /// so the object has a status — the encoding just does not spell it.
    ///
    /// `None` means the code is one this draft leaves unassigned, and so one it
    /// gives no payload rule for. That is not reachable through
    /// [`SubgroupObjectReader::read_object_meta`], which refuses such a code
    /// before it can reach the field, but the fields here are public and a meta
    /// assembled by hand — by a relay carrying a status across from a draft
    /// that numbers them differently, say — can hold anything a varint can. The
    /// answer there is that this draft has none, not that the payload is
    /// forbidden.
    pub fn payload_permission(&self) -> Option<PayloadPermission> {
        match self.status {
            None => Some(PayloadPermission::Permitted),
            Some(code) => ObjectStatus::from_u64(code).map(PayloadPermission::for_status),
        }
    }
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
        check_extensions_against_status(
            status.map(|s| s.as_u64()),
            extension_headers.len() as u64,
        )?;

        Ok(SubgroupObject { object_id, extension_headers, status, payload })
    }

    /// Decode the next object's framing without copying its payload.
    ///
    /// Consumes exactly the bytes [`Self::read_object`] consumes and leaves
    /// the same delta state behind, so the two are interchangeable on a
    /// given stream.
    pub fn read_object_meta(
        &mut self,
        buf: &mut impl Buf,
    ) -> Result<SubgroupObjectMeta, CodecError> {
        let start = buf.remaining();
        let delta = VarInt::decode(buf)?.into_inner();
        let object_id_val = match self.prev_object_id {
            None => delta,
            Some(prev) => prev
                .checked_add(1)
                .and_then(|v| v.checked_add(delta))
                .ok_or(CodecError::InvalidField)?,
        };
        self.prev_object_id = Some(object_id_val);
        let object_id =
            VarInt::from_u64(object_id_val).map_err(|_| CodecError::InvalidField)?.into_inner();

        let extension_headers_len = if self.extensions_present {
            let ext_len = VarInt::decode(buf)?.into_inner();
            skip(buf, ext_len)?;
            ext_len
        } else {
            0
        };

        let payload_length = VarInt::decode(buf)?.into_inner();
        let status = if payload_length == 0 {
            let status_val = VarInt::decode(buf)?.into_inner();
            Some(ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?.as_u64())
        } else {
            skip(buf, payload_length)?;
            None
        };
        check_extensions_against_status(status, extension_headers_len)?;

        Ok(SubgroupObjectMeta {
            object_id,
            extension_headers_len,
            payload_length,
            status,
            wire_len: (start - buf.remaining()) as u64,
        })
    }

    /// Serialize a subgroup object using the reader's delta state. Intended
    /// for senders that want to build a stream incrementally — tracks
    /// `prev_object_id` so successive calls produce correct deltas.
    ///
    /// Returns an error if `object.object_id <= prev_object_id`, which
    /// would produce an invalid delta.
    ///
    /// It also refuses the three shapes the stream cannot carry, rather than
    /// writing whichever half fits and dropping the rest:
    ///
    /// * A non-empty payload beside a status other than Normal. Section
    ///   10.2.1.1: "Any object with a status code other than zero MUST have an
    ///   empty payload." A truncated payload is worse than a refusal — the
    ///   receiver has no way to tell that anything was there.
    /// * Extension headers on an object whose stream type says the subgroup has
    ///   none. The type byte is fixed for the whole stream by the header, so
    ///   this object cannot opt in, and its extensions would simply vanish.
    /// * Extension headers on an Object Does Not Exist status, per Section
    ///   10.2.1.2.
    ///
    /// Normal beside a non-empty payload is not one of those and is written as
    /// an ordinary payload-bearing object: it is the status such an object
    /// already has, so naming it asks for the bytes leaving it out asks for.
    /// Normal beside an empty payload keeps the explicit status form, which is
    /// the only way to send a zero-length object at all.
    pub fn write_object(
        &mut self,
        object: &SubgroupObject,
        buf: &mut impl BufMut,
    ) -> Result<(), CodecError> {
        let explicit_status = match object.status {
            Some(status) if status != ObjectStatus::Normal => {
                if !object.payload.is_empty() {
                    return Err(CodecError::InvalidField);
                }
                Some(status)
            }
            Some(ObjectStatus::Normal) if object.payload.is_empty() => Some(ObjectStatus::Normal),
            _ => None,
        };
        if !self.extensions_present && !object.extension_headers.is_empty() {
            return Err(CodecError::InvalidField);
        }
        check_extensions_against_status(
            explicit_status.map(|s| s.as_u64()),
            object.extension_headers.len() as u64,
        )?;

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
        if let Some(status) = explicit_status {
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

/// Which failure a leading unidirectional stream type that is not the one a
/// reader wants is.
///
/// Section 10: "An endpoint that receives an unknown stream or datagram type
/// MUST close the session." One sentence, two tables. The stream table assigns
/// 0x05 for FETCH_HEADER and the range 0x10 to 0x1D for SUBGROUP_HEADER;
/// everything outside them is unknown at the head of a stream, and the session
/// ends.
///
/// The two assigned kinds are what the [`CodecError::InvalidField`] arm is for:
/// a fetch stream reaching the subgroup reader, or a subgroup stream reaching
/// the fetch reader, is a value this draft defines, and the disagreement is
/// with the reader that was called rather than with the draft. Reporting it as
/// unknown would end sessions over streams draft-14 permits.
///
/// Values above 0xFF land here too. None of them is assigned — this draft
/// carries its control messages on a bidirectional stream and so has no
/// multi-byte unidirectional type the way drafts 17 and later do.
fn stream_type_error(raw: u64) -> CodecError {
    let assigned = raw == FETCH_STREAM_TYPE as u64
        || (raw <= 0xFF && SubgroupStreamType::from_u8(raw as u8).is_some());
    if assigned {
        CodecError::InvalidField
    } else {
        CodecError::UnknownStreamType(raw)
    }
}

/// Draft-14 fetch stream type byte.
pub const FETCH_STREAM_TYPE: u8 = 0x05;

/// Fetch stream header: the type byte `0x05` followed by the Request ID.
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

    /// Decode the header.
    ///
    /// Errors with [`CodecError::UnknownStreamType`] when the stream table does
    /// not assign the leading type, which this draft answers with a close, and
    /// with [`CodecError::InvalidField`] for the subgroup types, which it does
    /// assign. `stream_type_error` draws that line.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_val = VarInt::decode(buf)?.into_inner();
        if type_val != FETCH_STREAM_TYPE as u64 {
            return Err(stream_type_error(type_val));
        }
        let request_id = VarInt::decode(buf)?;
        Ok(FetchHeader { request_id })
    }
}

/// One object carried on a fetch stream.
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

/// The framing of one fetch object, without its payload.
///
/// Produced by [`FetchObject::decode_meta`] for callers that forward an
/// object's bytes verbatim and never inspect the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchObjectMeta {
    /// Group ID.
    pub group_id: u64,
    /// Subgroup ID.
    pub subgroup_id: u64,
    /// Object ID.
    pub object_id: u64,
    /// Publisher priority.
    pub publisher_priority: u8,
    /// Byte length of the extension-header block's contents, excluding its
    /// length prefix.
    pub extension_headers_len: u64,
    /// Declared payload length. Zero when `status` is `Some`.
    pub payload_length: u64,
    /// Object Status wire code, present only when the payload is empty.
    pub status: Option<u64>,
    /// Total bytes this object occupies on the wire, prefix fields included.
    pub wire_len: u64,
}

impl FetchObjectMeta {
    /// Whether this object's status permits it a non-empty payload.
    ///
    /// The fetch-stream twin of [`SubgroupObjectMeta::payload_permission`], and
    /// it answers on the same terms: `None` for a code this draft does not
    /// assign, and [`PayloadPermission::Permitted`] for an absent status, which
    /// a meta has only when its payload length is non-zero.
    pub fn payload_permission(&self) -> Option<PayloadPermission> {
        match self.status {
            None => Some(PayloadPermission::Permitted),
            Some(code) => ObjectStatus::from_u64(code).map(PayloadPermission::for_status),
        }
    }
}

impl FetchObject {
    /// The status this object resolves to.
    ///
    /// The wire carries a status field only on an empty object, so an object
    /// holding bytes is [`ObjectStatus::Normal`] whatever `status` says.
    pub fn status(&self) -> ObjectStatus {
        if self.payload.is_empty() {
            self.status.unwrap_or(ObjectStatus::Normal)
        } else {
            ObjectStatus::Normal
        }
    }

    /// Whether this object's status permits it a non-empty payload.
    ///
    /// Answered from the status alone, for the reason
    /// [`SubgroupObject::permits_payload`] gives. Note that
    /// [`Self::encode_checked`] refuses the pairing this reports on, so a
    /// `false` here is a value that will not be written rather than one
    /// already on the wire.
    pub fn permits_payload(&self) -> bool {
        PayloadPermission::for_status(self.status()).permits()
    }

    /// Encode one fetch object, refusing a value the wire shape cannot carry.
    ///
    /// A fetch object holds a status and a payload in the same value, and the
    /// wire form has room for only one: the Object Status field is written only
    /// when Object Payload Length is zero. [`Self::encode`] settles that by
    /// following the status and dropping the payload, which loses the payload
    /// without saying so. This refuses instead, before any byte is written, so
    /// a rejected object leaves `buf` untouched.
    ///
    /// Section 10.2.1.1: "Any object with a status code other than zero MUST
    /// have an empty payload." Normal beside a payload is therefore not a
    /// disagreement — it is the status a payload-bearing object already has —
    /// and it is written as an ordinary payload-bearing object.
    ///
    /// Extension headers on an Object Does Not Exist status are refused for the
    /// separate reason given in Section 10.2.1.2.
    ///
    /// Unlike a subgroup stream, a fetch object always carries its Extension
    /// Headers Length field, so a length of zero is an ordinary object with no
    /// extensions and is written as such.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        if matches!(self.status, Some(status) if status != ObjectStatus::Normal)
            && !self.payload.is_empty()
        {
            return Err(CodecError::InvalidField);
        }
        check_extensions_against_status(
            self.status.map(|s| s.as_u64()),
            self.extension_headers.len() as u64,
        )?;
        self.encode(buf);
        Ok(())
    }

    /// Encode one fetch object.
    ///
    /// Infallible because the status is taken as the authority on framing, and
    /// lossy for the same reason: a payload set beside a status is discarded
    /// here without a word. Prefer [`Self::encode_checked`], which refuses that
    /// combination rather than resolving it.
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
        check_extensions_against_status(
            status.map(|s| s.as_u64()),
            extension_headers.len() as u64,
        )?;
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

    /// Decode one fetch object's framing without copying its payload.
    ///
    /// Consumes exactly the bytes [`Self::decode`] consumes.
    pub fn decode_meta(buf: &mut impl Buf) -> Result<FetchObjectMeta, CodecError> {
        let start = buf.remaining();
        let group_id = VarInt::decode(buf)?.into_inner();
        let subgroup_id = VarInt::decode(buf)?.into_inner();
        let object_id = VarInt::decode(buf)?.into_inner();
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        let extension_headers_len = VarInt::decode(buf)?.into_inner();
        skip(buf, extension_headers_len)?;
        let payload_length = VarInt::decode(buf)?.into_inner();
        let status = if payload_length == 0 {
            let status_val = VarInt::decode(buf)?.into_inner();
            Some(ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?.as_u64())
        } else {
            skip(buf, payload_length)?;
            None
        };
        check_extensions_against_status(status, extension_headers_len)?;
        Ok(FetchObjectMeta {
            group_id,
            subgroup_id,
            object_id,
            publisher_priority,
            extension_headers_len,
            payload_length,
            status,
            wire_len: (start - buf.remaining()) as u64,
        })
    }
}

// ============================================================
// Datagram (Type 0x00..=0x07, 0x20..=0x21)
// ============================================================

/// Datagram type byte.
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
        // variants (0x20/0x21) always carry an Object ID.
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

/// Datagram carrying a single object.
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
    /// Encode the datagram in full, refusing a field the type byte cannot
    /// carry.
    ///
    /// Draft-14 Section 10.3.1 states the framing rule outright: "The Object
    /// Status field and Object Payload are mutually exclusive." Types 0x00
    /// through 0x07 carry a payload and omit the status field; types 0x20 and
    /// 0x21 carry a status field and have no payload. This value can hold both
    /// at once, and [`Self::encode`] resolves the disagreement by writing
    /// whichever one the type byte announces and discarding the other without a
    /// word. An End of Group marker written under a payload type does not
    /// arrive late or malformed — it does not arrive at all, and the receiver
    /// sees an ordinary object in its place; a payload written under a status
    /// type vanishes the same way.
    ///
    /// [`ObjectStatus::Normal`] under a payload type is not that case and is
    /// accepted. Section 10.2.1.1 says "Any object with a status code other
    /// than zero MUST have an empty payload", so Normal is the status a
    /// payload-bearing object already has, and stating it asks for exactly the
    /// bytes leaving it out asks for.
    ///
    /// Errors with [`CodecError::InvalidField`] on either lossy combination,
    /// before any byte is written, so a refused datagram leaves `buf`
    /// untouched.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        if self.datagram_type.is_status() {
            if !self.payload.is_empty() {
                return Err(CodecError::InvalidField);
            }
        } else if matches!(self.status, Some(status) if status != ObjectStatus::Normal) {
            return Err(CodecError::InvalidField);
        }
        // The extension block is the other field the type byte governs, and it
        // is governed in both directions. A type that announces extensions must
        // carry some, because Section 10.3.1 makes a declared length of 0 a
        // session-closing offence on receipt; a type that announces none cannot
        // carry any, and `encode` would drop them in silence.
        if self.datagram_type.extensions_present() {
            if self.extension_headers.is_empty() {
                return Err(CodecError::InvalidField);
            }
        } else if !self.extension_headers.is_empty() {
            return Err(CodecError::InvalidField);
        }
        check_extensions_against_status(
            self.status.map(|s| s.as_u64()),
            self.extension_headers.len() as u64,
        )?;
        self.encode(buf);
        Ok(())
    }

    /// Encode the datagram in full.
    ///
    /// The type byte is taken as the authority on framing, which is what makes
    /// this infallible — and what makes it lossy when the value disagrees with
    /// itself. A `status` set under a payload type, or a `payload` set under a
    /// status type, is discarded here without a word. Prefer
    /// [`Self::encode_checked`], which refuses those combinations instead of
    /// resolving them.
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
            return Err(CodecError::UnknownDatagramType(type_val));
        }
        let datagram_type = DatagramType::from_u8(type_val as u8)
            .ok_or(CodecError::UnknownDatagramType(type_val))?;
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
            // Section 10.3.1: "If an endpoint receives a datagram with
            // Extensions Present as 'Yes' and a Extension Headers Length of 0,
            // it MUST close the session with PROTOCOL_VIOLATION." A datagram
            // with no extensions has a type byte that says so, and the two
            // spellings of "no extensions" are not interchangeable here.
            //
            // Subgroup streams say the opposite in Section 10.4.2 — there the
            // type byte is fixed for the whole stream, so an object with no
            // extensions has nowhere to say it but a length of 0. Only the
            // datagram carries this rule.
            if ext_len == 0 {
                return Err(CodecError::InvalidField);
            }
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
        check_extensions_against_status(
            status.map(|s| s.as_u64()),
            extension_headers.len() as u64,
        )?;
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
        // 0x16 falls in the gap between the two ranges Table 4 assigns,
        // 0x10-0x15 and 0x18-0x1D, so no table names it. Draft-14 states no
        // list of invalid Types the way drafts 16 and later do — the value is
        // simply one it does not have, which Section 10 answers by ending the
        // session.
        let buf = [0x16u8, 0x01, 0x00, 0x80];
        let err = SubgroupHeader::decode(&mut &buf[..]).unwrap_err();
        assert!(
            matches!(err, CodecError::UnknownStreamType(0x16)),
            "an unassigned Type must be named as one, got {err:?}"
        );
    }

    #[test]
    fn subgroup_header_decode_does_not_call_the_fetch_type_unknown() {
        // 0x05 is FETCH_HEADER, which Table 4 assigns. A subgroup reader
        // refuses it, but the disagreement is with the caller rather than with
        // the draft, so it must not reach for the rule that ends the session.
        let buf = [0x05u8, 0x01, 0x00, 0x80];
        let err = SubgroupHeader::decode(&mut &buf[..]).unwrap_err();
        assert!(
            matches!(err, CodecError::InvalidField),
            "a fetch stream at the subgroup reader must be refused without naming the \
             unknown-stream-type rule, got {err:?}"
        );
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

    #[test]
    fn subgroup_reader_meta_matches_read_object() {
        // Type 0x11: extensions present, so every field is exercised.
        let header = SubgroupHeader {
            stream_type: SubgroupStreamType::from_u8(0x11).unwrap(),
            track_alias: vi(1),
            group_id: vi(0),
            subgroup_id: None,
            publisher_priority: 0,
        };
        let mut write = SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        for (id, status) in
            [(0u64, None), (4, Some(ObjectStatus::EndOfGroup)), (9, None)].into_iter()
        {
            write
                .write_object(
                    &SubgroupObject {
                        object_id: vi(id),
                        extension_headers: vec![0x0A, 0x0B],
                        status,
                        payload: if status.is_some() { vec![] } else { vec![0xEE; 3] },
                    },
                    &mut buf,
                )
                .unwrap();
        }

        let mut full = SubgroupObjectReader::new(&header);
        let mut meta = SubgroupObjectReader::new(&header);
        let mut full_cursor = &buf[..];
        let mut meta_cursor = &buf[..];
        for _ in 0..3 {
            let before = meta_cursor.remaining();
            let o = full.read_object(&mut full_cursor).unwrap();
            let m = meta.read_object_meta(&mut meta_cursor).unwrap();
            assert_eq!(m.object_id, o.object_id.into_inner());
            assert_eq!(m.extension_headers_len, o.extension_headers.len() as u64);
            assert_eq!(m.payload_length, o.payload.len() as u64);
            assert_eq!(m.status, o.status.map(|s| s.as_u64()));
            assert_eq!(m.wire_len, (before - meta_cursor.remaining()) as u64);
            assert_eq!(full_cursor.remaining(), meta_cursor.remaining());
        }
        assert!(meta_cursor.is_empty());
    }

    #[test]
    fn subgroup_reader_meta_short_buffer_is_unexpected_end() {
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
                    object_id: vi(0),
                    extension_headers: vec![],
                    status: None,
                    payload: vec![1, 2, 3, 4],
                },
                &mut buf,
            )
            .unwrap();

        for cut in 1..buf.len() {
            let mut read = SubgroupObjectReader::new(&header);
            let err = read.read_object_meta(&mut &buf[..cut]).unwrap_err();
            assert!(
                matches!(err, CodecError::UnexpectedEnd | CodecError::VarInt(_)),
                "cut {cut} gave {err:?}"
            );
        }
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

    #[test]
    fn fetch_object_meta_matches_decode() {
        for obj in [
            FetchObject {
                group_id: vi(3),
                subgroup_id: vi(1),
                object_id: vi(7),
                publisher_priority: 200,
                extension_headers: vec![0xAA, 0xBB],
                status: None,
                payload: vec![1, 2, 3, 4],
            },
            FetchObject {
                group_id: vi(4),
                subgroup_id: vi(0),
                object_id: vi(8),
                publisher_priority: 1,
                extension_headers: vec![],
                status: Some(ObjectStatus::EndOfTrack),
                payload: vec![],
            },
        ] {
            let mut buf = Vec::new();
            obj.encode(&mut buf);
            let mut decode_cursor = &buf[..];
            let mut meta_cursor = &buf[..];
            let decoded = FetchObject::decode(&mut decode_cursor).unwrap();
            let meta = FetchObject::decode_meta(&mut meta_cursor).unwrap();
            assert_eq!(meta.group_id, decoded.group_id.into_inner());
            assert_eq!(meta.subgroup_id, decoded.subgroup_id.into_inner());
            assert_eq!(meta.object_id, decoded.object_id.into_inner());
            assert_eq!(meta.publisher_priority, decoded.publisher_priority);
            assert_eq!(meta.extension_headers_len, decoded.extension_headers.len() as u64);
            assert_eq!(meta.payload_length, decoded.payload.len() as u64);
            assert_eq!(meta.status, decoded.status.map(|s| s.as_u64()));
            assert_eq!(meta.wire_len, buf.len() as u64);
            assert!(meta_cursor.is_empty());
            assert_eq!(decode_cursor.remaining(), meta_cursor.remaining());
        }
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

    /// A datagram under `type_byte` holding both `status` and `payload`.
    fn datagram(type_byte: u8, status: Option<ObjectStatus>, payload: Vec<u8>) -> DatagramObject {
        DatagramObject {
            datagram_type: DatagramType::from_u8(type_byte).unwrap(),
            track_alias: vi(1),
            group_id: vi(0),
            object_id: vi(0),
            publisher_priority: 128,
            extension_headers: vec![],
            status,
            payload,
        }
    }

    /// Neither of the two fields the type byte cannot carry is dropped in
    /// silence; both are refused.
    ///
    /// Draft-14 Section 10.3.1: "The Object Status field and Object Payload are
    /// mutually exclusive." Types 0x00 through 0x07 write a payload and no
    /// status; types 0x20 and 0x21 write a status and no payload. A
    /// [`DatagramObject`] can hold both at once, and [`DatagramObject::encode`]
    /// resolves that by writing whichever the type byte announces and
    /// discarding the other — the loss this gate exists for. The middle of each
    /// half observes the discard directly, so the gate states the old behaviour
    /// as well as the new.
    ///
    /// Normal beside a payload is exempt and checked at the end. Section
    /// 10.2.1.1 says "Any object with a status code other than zero MUST have
    /// an empty payload", so Normal is the status a payload-bearing object
    /// already has, and naming it asks for the same bytes as leaving it out.
    ///
    /// # What this catches, observed by making each change and running it
    ///
    /// Dropping the status half of the check, leaving the type byte to decide
    /// as it did before:
    ///
    /// ```text
    /// encode_checked must refuse ObjectDoesNotExist under a payload type; got Ok(())
    /// ```
    ///
    /// Dropping the payload half instead:
    ///
    /// ```text
    /// encode_checked must refuse a payload under a status type; got Ok(())
    /// ```
    ///
    /// Widening the status half to refuse Normal beside a payload as well:
    ///
    /// ```text
    /// encode_checked refused a Normal status under a payload type: InvalidField
    /// ```
    #[test]
    fn encode_checked_refuses_the_field_the_type_byte_cannot_carry() {
        for &status in ObjectStatus::ALL {
            if status == ObjectStatus::Normal {
                continue;
            }

            // A status under a payload type: the status is what would go.
            let object = datagram(0x00, Some(status), vec![0xDE, 0xAD]);
            let mut refused = Vec::new();
            let result = object.encode_checked(&mut refused);
            assert!(
                matches!(result, Err(CodecError::InvalidField)),
                "encode_checked must refuse {status:?} under a payload type; got {result:?}"
            );
            assert!(refused.is_empty(), "a refused {status:?} datagram still wrote {refused:?}");

            let mut dropped = Vec::new();
            object.encode(&mut dropped);
            let decoded = DatagramObject::decode(&mut &dropped[..])
                .unwrap_or_else(|e| panic!("the lossy encoding of {status:?} must parse: {e:?}"));
            assert_eq!(decoded.status, None, "{status:?} is exactly what `encode` loses here");
            assert_eq!(decoded.payload, vec![0xDE, 0xAD]);

            // The same status under a status type is representable, so it is
            // written and read back unchanged.
            let mut carried = Vec::new();
            datagram(0x20, Some(status), vec![]).encode_checked(&mut carried).unwrap_or_else(|e| {
                panic!("encode_checked refused a status-type {status:?}: {e:?}")
            });
            let decoded = DatagramObject::decode(&mut &carried[..]).unwrap();
            assert_eq!(decoded.status, Some(status), "{status:?} lost its status");
        }

        // A payload under a status type: now the payload is what would go.
        let object = datagram(0x20, Some(ObjectStatus::EndOfGroup), vec![0xDE, 0xAD]);
        let mut refused = Vec::new();
        let result = object.encode_checked(&mut refused);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "encode_checked must refuse a payload under a status type; got {result:?}"
        );
        assert!(refused.is_empty(), "a refused datagram still wrote {refused:?}");

        let mut dropped = Vec::new();
        object.encode(&mut dropped);
        let decoded = DatagramObject::decode(&mut &dropped[..]).unwrap();
        assert!(decoded.payload.is_empty(), "the payload is exactly what `encode` loses here");
        assert_eq!(decoded.status, Some(ObjectStatus::EndOfGroup));

        // Normal beside a payload asks for the bytes a payload datagram
        // already writes, so it is accepted and writes exactly those.
        let mut named = Vec::new();
        datagram(0x00, Some(ObjectStatus::Normal), vec![0xDE, 0xAD])
            .encode_checked(&mut named)
            .unwrap_or_else(|e| {
                panic!("encode_checked refused a Normal status under a payload type: {e:?}")
            });
        let mut unnamed = Vec::new();
        datagram(0x00, None, vec![0xDE, 0xAD]).encode_checked(&mut unnamed).unwrap();
        assert_eq!(named, unnamed, "naming Normal must ask for the bytes leaving it out asks for");
    }
}

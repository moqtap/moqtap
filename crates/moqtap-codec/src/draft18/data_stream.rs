//! Draft-18 data stream header encoding and decoding.
//!
//! Subgroup header type byte, draft-18 Section 11.4.2: the form is
//! 0b0XX1XXXX, so bit 7 is clear and bit 4 is set, giving the ranges
//! 0x10..0x1F, 0x30..0x3F, 0x50..0x5F, 0x70..0x7F.
//!   - bit 0 (0x01): PROPERTIES
//!   - bits 1-2 (0x06): SUBGROUP_ID_MODE (0=zero, 1=first_obj, 2=explicit, 3=reserved)
//!   - bit 3 (0x08): END_OF_GROUP
//!   - bit 5 (0x20): DEFAULT_PRIORITY (no priority byte)
//!   - bit 6 (0x40): FIRST_OBJECT (new in draft-18)
//!
//! Datagram type byte, draft-18 Section 11.3.1: the form is 0b00X0XXXX, so
//! bits 7, 6 and 4 are clear, giving the ranges 0x00..0x0F and 0x20..0x2F.
//!   - bit 0 (0x01): PROPERTIES
//!   - bit 1 (0x02): END_OF_GROUP
//!   - bit 2 (0x04): ZERO_OBJECT_ID (object_id=0, field omitted)
//!   - bit 3 (0x08): DEFAULT_PRIORITY (no priority byte)
//!   - bit 5 (0x20): STATUS (status byte replaces payload)
//!
//! Both sections then list the Type values inside those ranges that are
//! nonetheless invalid, and answer each with "MUST close the session with a
//! PROTOCOL_VIOLATION": SUBGROUP_ID_MODE 0b11 on a stream header, and STATUS
//! together with END_OF_GROUP on a datagram. Both decoders refuse them, and so
//! do `SubgroupHeader::encode_checked` and `DatagramHeader::encode_checked`,
//! which write only what those decoders accept.
//!
//! Fetch header: stream type 0x05 + request_id, then objects whose fields are
//! selected by a Serialization Flags varint and resolved against the object
//! before them (Section 11.4.4). `FetchObjectHeader` is the wire frame and
//! `FetchObjectReader` resolves it.
//!
//! Padding, Section 11.5, is a stream type and a datagram type of its own —
//! `PADDING_STREAM_TYPE` and `PADDING_DATAGRAM_TYPE` — carrying no Objects.
//! Neither is a subgroup header or a datagram header, and this module's
//! decoders refuse both rather than reading a padding frame's leading bytes as
//! header fields.

use bytes::{Buf, BufMut};

use super::types::ObjectStatus;
use crate::error::CodecError;
use crate::varint::{Moqt18 as Wire, VarInt};

/// Advance `buf` past `len` bytes without copying them.
fn skip(buf: &mut impl Buf, len: u64) -> Result<(), CodecError> {
    let len = usize::try_from(len).map_err(|_| CodecError::UnexpectedEnd)?;
    if buf.remaining() < len {
        return Err(CodecError::UnexpectedEnd);
    }
    buf.advance(len);
    Ok(())
}

/// Turn a wire Object Status code into an [`ObjectStatus`], refusing one
/// draft-18 does not assign.
///
/// Draft-18 Section 11.2.1.1 lists the codes an object may carry and says any
/// other value SHOULD be treated as a protocol error and the session closed
/// with a PROTOCOL_VIOLATION. Every place this module reads a status converts
/// it here, so a decoded [`SubgroupObject::object_status`] or
/// [`DatagramHeader::object_status`] is always a status the draft assigns, and
/// [`SubgroupObjectMeta::status`] — which stays a raw code because a relay may
/// carry it to a draft that numbers the set differently — holds one because it
/// comes from the same conversion.
fn decoded_status(code: u64) -> Result<ObjectStatus, CodecError> {
    ObjectStatus::from_u64(code).ok_or(CodecError::InvalidField)
}

// ── Padding ───────────────────────────────────────────────────

/// Unidirectional stream type for padding, draft-18 Section 11.5.1: "An
/// endpoint MAY open a unidirectional stream with a stream type of 0x132B3E28
/// to send padding data. The stream begins with the stream type, followed by
/// zero or more bytes that MUST all be set to zero."
///
/// Named here because the value is what tells a padding stream from a data
/// stream, and nothing else in this module would otherwise say so. Under the
/// draft-18 variable-length integer encoding (Section 1.4.1) the value takes
/// five bytes, the first of which is 0xF0 — an octet with bit 4 set, which is
/// how a padding stream came to look like a subgroup header rather than like a
/// frame to refuse.
pub const PADDING_STREAM_TYPE: u64 = 0x132B_3E28;

/// Datagram type for padding, draft-18 Section 11.5.2: "An endpoint MAY send a
/// datagram with a type of 0x132B3E29 to send padding data. The datagram
/// contains the type followed by zero or more bytes that MUST all be set to
/// zero."
///
/// One more than [`PADDING_STREAM_TYPE`] and encoded the same width, so a
/// padding datagram is refused by [`DatagramHeader::decode`] for the same
/// reason: its leading byte is outside every form Section 11.3.1 defines.
pub const PADDING_DATAGRAM_TYPE: u64 = 0x132B_3E29;

/// Whether an Object carrying a given status is permitted a non-empty payload.
///
/// Draft-18 Section 11.2.1.1 states the rule in one sentence — "Any object with
/// a status code other than zero MUST have an empty payload" — so unlike a
/// draft that gives its Object Status registry a payload column, there is no
/// per-status datum to carry around: the answer is derived from the code, and
/// this type is the answer rather than the source of it.
///
/// It exists so a caller can ask the question without restating the rule. A
/// caller that reaches for the status code and compares it to zero has copied
/// the sentence into its own source, where it cannot follow the draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadPermission {
    /// The status permits a payload but does not require one: a zero-length
    /// Object with such a status is well formed. Only Normal, on draft-18.
    Permitted,
    /// An Object with such a status has an empty payload, and one carrying
    /// bytes is malformed.
    Forbidden,
}

impl PayloadPermission {
    /// `true` for [`PayloadPermission::Permitted`].
    pub fn permits(self) -> bool {
        matches!(self, PayloadPermission::Permitted)
    }
}

/// The payload permission draft-18 Section 11.2.1.1 gives `status`.
///
/// Normal is the one status that permits a payload; every other assigned status
/// forbids one. Kept as a function of [`ObjectStatus`] rather than of the raw
/// code so that a status the draft does not assign cannot reach it — such a
/// code has no permission, because the draft states no rule for a value it
/// never assigned.
fn payload_permission_of(status: ObjectStatus) -> PayloadPermission {
    match status {
        ObjectStatus::Normal => PayloadPermission::Permitted,
        ObjectStatus::EndOfGroup | ObjectStatus::EndOfTrack => PayloadPermission::Forbidden,
    }
}

// ── Subgroup ──────────────────────────────────────────────────

const SUBGROUP_PROPERTIES_BIT: u8 = 0x01;
const SUBGROUP_ID_MODE_MASK: u8 = 0x06;
const SUBGROUP_END_OF_GROUP_BIT: u8 = 0x08;
const SUBGROUP_BASE_BIT: u8 = 0x10;
const SUBGROUP_DEFAULT_PRIORITY_BIT: u8 = 0x20;
const SUBGROUP_FIRST_OBJECT_BIT: u8 = 0x40;

/// The bits the subgroup header form 0b0XX1XXXX fixes: bit 7 and bit 4.
const SUBGROUP_FORM_MASK: u8 = 0x90;
/// The values the form fixes them to: bit 7 clear, bit 4 set.
const SUBGROUP_FORM_VALUE: u8 = SUBGROUP_BASE_BIT;
/// The SUBGROUP_ID_MODE value draft-18 reserves for future use.
const SUBGROUP_ID_MODE_RESERVED: u8 = 0b11;

/// Whether `header_type` is a Type value draft-18 Section 11.4.2 allows on a
/// subgroup stream.
///
/// The section gives the form and then lists what is invalid inside it,
/// answering both with "MUST close the session with a PROTOCOL_VIOLATION":
///
/// - "Type values that do not match the form 0b0XX1XXXX (i.e., Type values
///   outside the ranges 0x10..0x1F, 0x30..0x3F, 0x50..0x5F, and 0x70..0x7F, or
///   values where bit 4 is not set)." Bit 7 is part of that form: a value with
///   it set is outside all four ranges, and is how a padding stream
///   (Section 11.5.1) arrives, since [`PADDING_STREAM_TYPE`] leads with 0xF0.
/// - "Type values with SUBGROUP_ID_MODE set to 0b11: 0x16, 0x17, 0x1E, 0x1F,
///   0x36, 0x37, 0x3E, 0x3F, 0x56, 0x57, 0x5E, 0x5F, 0x76, 0x77, 0x7E, 0x7F.
///   This mode is reserved for future use."
fn subgroup_type_is_valid(raw: u64) -> bool {
    raw <= 0xFF && {
        let t = raw as u8;
        t & SUBGROUP_FORM_MASK == SUBGROUP_FORM_VALUE
            && (t & SUBGROUP_ID_MODE_MASK) >> 1 != SUBGROUP_ID_MODE_RESERVED
    }
}

/// Whether `raw` sits inside the subgroup form but names the reserved
/// SUBGROUP_ID_MODE — the second of the two lists quoted above.
fn subgroup_type_is_reserved_mode(raw: u64) -> bool {
    raw <= 0xFF && {
        let t = raw as u8;
        t & SUBGROUP_FORM_MASK == SUBGROUP_FORM_VALUE
            && (t & SUBGROUP_ID_MODE_MASK) >> 1 == SUBGROUP_ID_MODE_RESERVED
    }
}

/// The unidirectional stream Type draft-18 Section 10.3 gives the control
/// stream.
const SETUP_STREAM_TYPE: u64 = 0x2F00;

/// Refuse a Type field spelled in more than one byte, before anything narrows
/// it to a byte.
///
/// Returns `Ok(None)` when the next Type is a single byte and the caller should
/// read it itself, `Ok(Some(err))` when it is wider and `refusal` has named the
/// failure, and `Err` only when the buffer does not hold the whole field yet.
///
/// Every Type the subgroup and datagram forms admit is below 0x80 and so
/// occupies one byte under the MoQT variable-length integer encoding. A wider
/// spelling is one of three things, and none of them may be read as a header:
/// an assigned Type that is not a data stream — SETUP or a padding stream — a
/// Type no table assigns, or a non-minimal spelling of a Type that is valid.
/// The last is the dangerous one: narrowing a two-byte 0x8001 to its low octet
/// turns it into an assigned Type, so a peer could name any Type it liked and
/// have it parsed as another.
///
/// The full varint is decoded before `refusal` sees it, which is what lets the
/// first case be told from the second. Only the second ends the session.
fn wide_type_refusal(
    buf: &mut impl Buf,
    refusal: fn(u64) -> CodecError,
) -> Result<Option<CodecError>, CodecError> {
    if !buf.has_remaining() {
        return Err(CodecError::UnexpectedEnd);
    }
    // Under the MoQT encoding the field's length is the number of leading 1
    // bits in its first byte plus one, so a first byte below 0x80 is the whole
    // of it.
    if buf.chunk()[0] < 0x80 {
        return Ok(None);
    }
    let raw = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
    Ok(Some(refusal(raw)))
}

/// Which failure a leading unidirectional stream Type that is not the one a
/// reader wants is.
///
/// Draft-18 states two rules about such a Type and answers both with a close,
/// and telling them apart is the whole job of this function.
///
/// Section 3.4 is about the table: "An endpoint that receives an unknown stream
/// type MUST close the session." A Type Table 3 does not assign is
/// [`CodecError::UnknownStreamType`].
///
/// Section 11.4.2 is about the subgroup form specifically, and the sixteen
/// Types inside it that name the reserved SUBGROUP_ID_MODE. Those are not
/// unknown — the form is assigned and the draft lists the values outright — but
/// they are unreadable, and they are [`CodecError::InvalidTypeValue`].
///
/// Table 3 assigns four things, and two of them carry no Objects at all:
/// FETCH_HEADER, the subgroup form, SETUP and PADDING. A subgroup reader handed
/// any of them refuses it as [`CodecError::InvalidField`] — the value is one
/// this draft defines, the disagreement is with the reader that was called, and
/// the session survives it.
///
/// The padding stream is the case that makes this worth the trouble. A peer may
/// open one at any time, and [`PADDING_STREAM_TYPE`] leads with 0xF0, so a
/// reader that judged the Type by its first byte would find bit 7 set, call the
/// stream unknown, and end a session over traffic Section 11.5.1 permits.
fn stream_type_error(raw: u64) -> CodecError {
    if raw == FETCH_STREAM_TYPE
        || raw == SETUP_STREAM_TYPE
        || raw == PADDING_STREAM_TYPE
        || subgroup_type_is_valid(raw)
    {
        CodecError::InvalidField
    } else if subgroup_type_is_reserved_mode(raw) {
        CodecError::InvalidTypeValue {
            raw,
            detail: "its SUBGROUP_ID_MODE is 0b11, which this draft reserves",
        }
    } else {
        CodecError::UnknownStreamType(raw)
    }
}

#[derive(Debug, Clone)]
pub struct SubgroupHeader {
    pub header_type: u8,
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub subgroup_id: VarInt,
    pub publisher_priority: Option<u8>,
}

impl SubgroupHeader {
    /// Decode a subgroup stream header, refusing a Type value the draft calls
    /// invalid.
    ///
    /// Refuses any Type value `subgroup_type_is_valid` rejects before reading
    /// anything after it. The refusal has to come first: every field behind the
    /// Type is present only because the Type says so, so a Type the draft does
    /// not define names no layout, and reading on produces a Track Alias and
    /// Group ID invented out of whatever bytes followed.
    ///
    /// A Type spelled in more than one byte is refused first, by
    /// `wide_type_refusal`, which decodes it in full so `stream_type_error`
    /// can tell a padding or SETUP stream — both assigned, both several bytes
    /// wide — from a Type Table 3 does not assign. Only the last of those ends
    /// the session.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        if let Some(err) = wide_type_refusal(buf, stream_type_error)? {
            return Err(err);
        }
        let raw = buf.get_u8() as u64;
        let header_type = raw as u8;

        if !subgroup_type_is_valid(raw) {
            return Err(stream_type_error(raw));
        }

        let track_alias = VarInt::decode_moqt::<Wire>(buf)?;
        let group_id = VarInt::decode_moqt::<Wire>(buf)?;

        let subgroup_id_mode = (header_type & SUBGROUP_ID_MODE_MASK) >> 1;
        let subgroup_id = match subgroup_id_mode {
            0 => VarInt::from_u64_moqt(0),
            2 => VarInt::decode_moqt::<Wire>(buf)?,
            // Mode 1: the Subgroup ID is the first object's ID, which is not
            // known until that object is read, so a placeholder zero stands in
            // and `subgroup_id_mode` is what says so. Mode 3 cannot reach
            // here — `subgroup_type_is_valid` refused it — and this arm covers
            // it only because the shift yields a `u8`.
            _ => VarInt::from_u64_moqt(0),
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
        self.track_alias.encode_moqt::<Wire>(buf);
        self.group_id.encode_moqt::<Wire>(buf);

        let subgroup_id_mode = (self.header_type & SUBGROUP_ID_MODE_MASK) >> 1;
        if subgroup_id_mode == 2 {
            self.subgroup_id.encode_moqt::<Wire>(buf);
        }

        if self.header_type & SUBGROUP_DEFAULT_PRIORITY_BIT == 0 {
            buf.put_u8(self.publisher_priority.unwrap_or(128));
        }
    }

    /// Serialize the header, refusing a Type value draft-18 does not define.
    ///
    /// The accepted set is the one [`Self::decode`] accepts, so bytes this
    /// writes always parse back through this module rather than being refused
    /// by the peer. Section 11.4.2 lists the excluded values under "The
    /// following Type values are invalid", and a receiver that follows it
    /// closes the session rather than reading the stream, so writing one loses
    /// the whole session and not merely the stream.
    ///
    /// Errors with [`CodecError::InvalidField`] before any byte is written, so
    /// a refused header leaves `buf` untouched rather than half a header the
    /// next write would run into.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        if !subgroup_type_is_valid(self.header_type as u64) {
            return Err(stream_type_error(self.header_type as u64));
        }
        self.encode(buf);
        Ok(())
    }

    pub fn has_properties(&self) -> bool {
        self.header_type & SUBGROUP_PROPERTIES_BIT != 0
    }

    /// The subgroup-ID mode: `(header_type & 0x06) >> 1`.
    ///
    /// `0` = no subgroup ID on the wire and it is zero; `1` = the subgroup ID
    /// is the first object's ID; `2` = an explicit ID follows the Group ID;
    /// `3` = reserved. Exposed because the mask is module-private and
    /// `dispatch::AnySubgroupHeader::subgroup_id_mode` cannot read it.
    pub fn subgroup_id_mode(&self) -> u8 {
        (self.header_type & SUBGROUP_ID_MODE_MASK) >> 1
    }

    pub fn is_end_of_group(&self) -> bool {
        self.header_type & SUBGROUP_END_OF_GROUP_BIT != 0
    }

    /// `true` when the FIRST_OBJECT bit (0x40) is set, signaling the first
    /// object on this stream is the original publisher's first object in the
    /// subgroup. Added in draft-18.
    pub fn is_first_object(&self) -> bool {
        self.header_type & SUBGROUP_FIRST_OBJECT_BIT != 0
    }
}

// ── Subgroup objects (stateful) ───────────────────────────────

/// One object within a draft-18 subgroup stream. Object IDs are
/// delta-encoded; whether a per-object "properties" block (the draft-18
/// equivalent of extension headers) is present depends on the PROPERTIES
/// bit on the enclosing [`SubgroupHeader`]. Use [`SubgroupObjectReader`]
/// to encode/decode.
#[derive(Debug, Clone)]
pub struct SubgroupObject {
    pub object_id: VarInt,
    /// Raw properties bytes, excluding the byte-length prefix that precedes
    /// them on the wire. Empty unless the subgroup header sets the
    /// PROPERTIES bit, or when the block is present but zero-length.
    /// Opaque: [`SubgroupObjectReader::write_object`] re-emits the prefix
    /// and these bytes verbatim.
    pub extension_headers: Vec<u8>,
    pub payload_length: VarInt,
    /// The object's status, carried on the wire only when `payload_length` is
    /// zero: a zero-length object encodes a status code in place of its
    /// payload. `None` with a zero `payload_length` is written as
    /// [`ObjectStatus::Normal`], the status draft-18 Section 11.2.1.1 gives an
    /// empty object.
    ///
    /// Typed rather than a raw code. The wire field is a varint with room for
    /// any value, and draft-18 assigns three of them; the decoder refuses the
    /// rest, and this type is that same refusal on the encode side — 0x1 and
    /// 0x2 cannot be named here, so [`SubgroupObjectReader::write_object`]
    /// cannot emit a status this module's own decoder would reject.
    pub object_status: Option<ObjectStatus>,
    pub payload: Vec<u8>,
}

impl SubgroupObject {
    /// The object's status, with the one draft-18's encoding elides filled in.
    ///
    /// A subgroup object states its status only when its Object Payload Length
    /// is zero. An object that carries bytes therefore has no status field, and
    /// its status is [`ObjectStatus::Normal`] — the only status draft-18
    /// Section 11.2.1.1 permits a payload, so the only one such an object could
    /// have had.
    pub fn status(&self) -> ObjectStatus {
        self.object_status.unwrap_or(ObjectStatus::Normal)
    }

    /// Whether this object's status is allowed to carry the properties it has.
    ///
    /// Draft-18 Section 11.2.1.2: "Any Object with status Normal can have
    /// properties (Section 2.5). If an endpoint receives properties on an Object with status
    /// that is not Normal, it MUST close the session with a
    /// PROTOCOL_VIOLATION."
    ///
    /// So this is `false` for exactly one shape: a non-empty properties block
    /// on an object whose status is not [`ObjectStatus::Normal`]. An object
    /// with no properties is fine at any status, and an object at Normal may
    /// carry any properties. A zero-length block is "no properties" here and
    /// not a violation — Section 11.4.2 requires it of an object on a
    /// PROPERTIES subgroup stream that has none: "Objects with no properties
    /// set Properties Length to 0."
    ///
    /// Neither [`SubgroupObjectReader::read_object`] nor
    /// [`SubgroupObjectReader::write_object`] applies this itself, which is a
    /// deliberate contrast with the payload rule beside it. A status next to a
    /// payload has no encoding — the two share a position on the wire — so the
    /// writer refuses it as unrepresentable. Properties next to a status encode
    /// fine; the frame is well formed and merely non-conforming, and a codec
    /// that could not read or write it could not reproduce a capture containing
    /// one. The rule addresses an endpoint receiving such an Object, so the
    /// endpoint is where it is enforced, and this is what it asks.
    ///
    /// The datagram carrier is the exception, and the draft is what makes it
    /// one: Section 11.3.1 states the same rule again as a per-datagram
    /// framing rule, so [`DatagramHeader::decode`] refuses it outright.
    pub fn properties_permitted(&self) -> bool {
        self.extension_headers.is_empty() || self.status() == ObjectStatus::Normal
    }
}

/// The framing of one draft-18 subgroup object, without its payload.
///
/// Produced by [`SubgroupObjectReader::read_object_meta`] for callers that
/// forward an object's bytes verbatim and never inspect the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubgroupObjectMeta {
    /// Resolved absolute Object ID.
    pub object_id: u64,
    /// Byte length of the properties block's contents, excluding its length
    /// prefix.
    pub extension_headers_len: u64,
    /// Declared payload length. Zero when `status` is `Some`.
    pub payload_length: u64,
    /// Object status wire code, present only when the payload is empty.
    pub status: Option<u64>,
    /// Total bytes this object occupies on the wire, prefix fields included.
    pub wire_len: u64,
}

impl SubgroupObjectMeta {
    /// Whether this object was allowed the payload bytes it declares, from
    /// draft-18 Section 11.2.1.1: "Any object with a status code other than
    /// zero MUST have an empty payload."
    ///
    /// `Some(Permitted)` when [`Self::status`] is `None`. A status reaches the
    /// wire only in place of a payload, so an object that declares one states
    /// no status — and the same section makes Normal "implicit for any
    /// non-zero length object", which is the status that permits the bytes.
    ///
    /// `Some(..)` from the status itself when there is one, which on a
    /// zero-length object is always the case.
    /// `None` when the status is a code draft-18 does not assign. Every meta
    /// this module decodes holds an assigned code — the module's status
    /// conversion refuses the rest before the meta is built — so `None` is
    /// reachable only from a meta assembled by hand, where the draft has no
    /// rule to report because it never assigned the code. It is deliberately
    /// not folded into `Forbidden`: *the draft says this may not carry a
    /// payload* and *the draft says nothing about this status* are different
    /// answers, and a caller that closes a session on the first should not
    /// close one on the second without deciding to.
    pub fn payload_permission(&self) -> Option<PayloadPermission> {
        match self.status {
            None => Some(PayloadPermission::Permitted),
            Some(code) => ObjectStatus::from_u64(code).map(payload_permission_of),
        }
    }
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
        let delta = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        let object_id_val = match self.prev_object_id {
            None => delta,
            Some(prev) => prev
                .checked_add(1)
                .and_then(|v| v.checked_add(delta))
                .ok_or(CodecError::ObjectIdOverflow(prev, delta))?,
        };
        self.prev_object_id = Some(object_id_val);
        let object_id = VarInt::from_u64(object_id_val).map_err(|_| CodecError::InvalidField)?;

        // The properties block is a byte-length-prefixed opaque blob. We
        // copy the blob verbatim; callers that want structured properties
        // can parse the returned bytes.
        let extension_headers = if self.extensions_present {
            let ext_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
            crate::types::read_bytes(buf, ext_len)?
        } else {
            Vec::new()
        };

        let payload_length_vi = VarInt::decode_moqt::<Wire>(buf)?;
        let payload_length_val = payload_length_vi.into_inner() as usize;
        let (object_status, payload) = if payload_length_val == 0 {
            let status = VarInt::decode_moqt::<Wire>(buf)?;
            (Some(decoded_status(status.into_inner())?), Vec::new())
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
        let delta = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        let object_id_val = match self.prev_object_id {
            None => delta,
            Some(prev) => prev
                .checked_add(1)
                .and_then(|v| v.checked_add(delta))
                .ok_or(CodecError::ObjectIdOverflow(prev, delta))?,
        };
        self.prev_object_id = Some(object_id_val);
        let object_id =
            VarInt::from_u64(object_id_val).map_err(|_| CodecError::InvalidField)?.into_inner();

        let extension_headers_len = if self.extensions_present {
            let ext_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
            skip(buf, ext_len)?;
            ext_len
        } else {
            0
        };

        let payload_length = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        let status = if payload_length == 0 {
            let code = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
            Some(decoded_status(code)?.as_u64())
        } else {
            skip(buf, payload_length)?;
            None
        };

        Ok(SubgroupObjectMeta {
            object_id,
            extension_headers_len,
            payload_length,
            status,
            wire_len: (start - buf.remaining()) as u64,
        })
    }

    /// Serialize an object, producing the correct delta encoding.
    ///
    /// A zero `payload_length` writes the object's status, defaulting to
    /// [`ObjectStatus::Normal`] when it is `None`. The status is typed, so
    /// every value that can reach this method is one draft-18 assigns and one
    /// [`Self::read_object`] accepts; there is no status-related error to
    /// return.
    ///
    /// Errors with [`CodecError::InvalidField`] when `object.object_id` is
    /// not strictly greater than the previously written object's ID, since
    /// no valid delta exists for that case.
    ///
    /// Errors with [`CodecError::InvalidField`] when `payload_length` is not
    /// exactly `payload.len()`. The declared length is written ahead of the
    /// payload, so a mismatch is a frame [`Self::read_object`] cannot parse
    /// and one no caller could fix by appending bytes.
    pub fn write_object(
        &mut self,
        object: &SubgroupObject,
        buf: &mut impl BufMut,
    ) -> Result<(), CodecError> {
        // A declared length that disagrees with the payload framed under it
        // produces bytes no reader can parse and no caller can repair: the
        // length is already on the wire ahead of the payload. Checked before
        // anything is written, so a refused object leaves `buf` untouched
        // rather than half an object the next read would run into.
        //
        // Zero is not "an empty payload" here; it is the marker that puts a
        // status code where the payload would go, so an object carrying bytes
        // under it is asking for two framings at once.
        let declared = object.payload_length.into_inner();
        if declared != object.payload.len() as u64 {
            return Err(CodecError::InvalidField);
        }

        let oid = object.object_id.into_inner();
        let delta = match self.prev_object_id {
            None => oid,
            Some(prev) => oid
                .checked_sub(prev)
                .and_then(|v| v.checked_sub(1))
                .ok_or(CodecError::InvalidField)?,
        };
        VarInt::from_u64(delta).map_err(|_| CodecError::InvalidField)?.encode_moqt::<Wire>(buf);
        if self.extensions_present {
            VarInt::from_u64(object.extension_headers.len() as u64)
                .map_err(|_| CodecError::InvalidField)?
                .encode_moqt::<Wire>(buf);
            buf.put_slice(&object.extension_headers);
        }
        object.payload_length.encode_moqt::<Wire>(buf);
        if object.payload_length.into_inner() == 0 {
            let status = object.object_status.unwrap_or(ObjectStatus::Normal);
            VarInt::from_u64_moqt(status.as_u64()).encode_moqt::<Wire>(buf);
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

/// The bits the datagram form 0b00X0XXXX fixes to zero: bits 7, 6 and 4.
const DATAGRAM_FORM_MASK: u8 = 0xD0;

/// Whether `datagram_type` is a Type value draft-18 Section 11.3.1 allows on a
/// datagram.
///
/// The section gives the form and then lists what is invalid inside it,
/// answering both with "MUST close the session with a PROTOCOL_VIOLATION":
///
/// - "Type values that do not match the form 0b00X0XXXX (i.e., Type values
///   outside the ranges 0x00..0x0F and 0x20..0x2F)." Three bits are fixed at
///   zero by that form — 7, 6 and 4 — and a padding datagram
///   (Section 11.5.2) is refused by it, since [`PADDING_DATAGRAM_TYPE`] leads
///   with 0xF0.
/// - "Type values with both the STATUS bit (0x20) and END_OF_GROUP bit (0x02)
///   set: 0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F. An object status
///   message cannot signal end of group."
fn datagram_type_is_valid(raw: u64) -> bool {
    raw <= 0xFF && {
        let t = raw as u8;
        t & DATAGRAM_FORM_MASK == 0 && t & STATUS_AND_END_OF_GROUP != STATUS_AND_END_OF_GROUP
    }
}

/// Both bits of the combination Section 11.3.1 forbids.
const STATUS_AND_END_OF_GROUP: u8 = DATAGRAM_STATUS_BIT | DATAGRAM_END_OF_GROUP_BIT;

/// Whether `raw` sits inside the datagram form but sets STATUS and END_OF_GROUP
/// together — the second of the two lists quoted above.
fn datagram_type_is_status_end_of_group(raw: u64) -> bool {
    raw <= 0xFF && {
        let t = raw as u8;
        t & DATAGRAM_FORM_MASK == 0 && t & STATUS_AND_END_OF_GROUP == STATUS_AND_END_OF_GROUP
    }
}

/// Which failure a leading datagram Type that is not one a reader wants is.
///
/// The same two-rule split as `stream_type_error`, read against the datagram
/// table: a Type outside the form is [`CodecError::UnknownDatagramType`], and
/// one inside it setting STATUS and END_OF_GROUP together is
/// [`CodecError::InvalidTypeValue`].
///
/// The padding datagram is why the [`CodecError::InvalidField`] arm exists.
/// [`PADDING_DATAGRAM_TYPE`] is a Type Table 3's companion in Section 11.5.2
/// assigns, so a datagram carrying it is not unknown; it simply carries no
/// Object, and refusing it must not end the session.
fn datagram_type_error(raw: u64) -> CodecError {
    if raw == PADDING_DATAGRAM_TYPE || datagram_type_is_valid(raw) {
        CodecError::InvalidField
    } else if datagram_type_is_status_end_of_group(raw) {
        CodecError::InvalidTypeValue {
            raw,
            detail: "it sets both the STATUS bit and the END_OF_GROUP bit",
        }
    } else {
        CodecError::UnknownDatagramType(raw)
    }
}

#[derive(Debug, Clone)]
pub struct DatagramHeader {
    pub datagram_type: u8,
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub object_id: VarInt,
    pub publisher_priority: Option<u8>,
    /// Raw properties bytes, excluding the byte-length prefix that precedes
    /// them on the wire. Present only when `datagram_type` sets the PROPERTIES
    /// bit (0x01), and empty otherwise — the bit is what puts the block on the
    /// wire, so contents held here with the bit clear are not written.
    ///
    /// Opaque: [`Self::encode`] re-emits the prefix and these bytes verbatim,
    /// and [`Self::decode`] copies them out the same way, so a datagram can be
    /// decoded and re-encoded without understanding what its properties mean.
    /// The block sits between the publisher priority and the status field, so
    /// leaving it out of the struct would put the status where the decoder
    /// looks for the properties length.
    pub properties: Vec<u8>,
    /// The object's status, carried on the wire only when `datagram_type` sets
    /// the STATUS bit (0x20): such a datagram holds a one-byte status code in
    /// place of a payload. `None` with the bit set is written as
    /// [`ObjectStatus::Normal`]; a status with the bit clear is not written at
    /// all, because the bit is what puts the field on the wire.
    ///
    /// Typed rather than a bare byte. The wire field is one octet with 256
    /// values, and draft-18 Section 11.2.1.1 assigns three of them; the
    /// decoder refuses the other 253, and this type is that same refusal on
    /// the encode side — [`Self::encode`] is infallible precisely because a
    /// status it could not legally write cannot be built.
    pub object_status: Option<ObjectStatus>,
}

impl DatagramHeader {
    /// Decode the header and stop, leaving whatever follows it in `buf`.
    ///
    /// A datagram's payload has no length field — draft-18 Section 11.3.1:
    /// "There is no explicit length field for the Object Payload; the entirety
    /// of the transport datagram following the Object header contains the
    /// payload." So the header alone cannot say how many bytes belong to the
    /// object, and this method deliberately does not try: the caller holds the
    /// transport datagram and the tail is theirs.
    ///
    /// That makes it the wrong entry point for validating the object as a
    /// whole. Use [`Self::decode_object`] when `buf` holds exactly one
    /// datagram; it consumes the tail and can therefore refuse a payload the
    /// framing forbids.
    ///
    /// Refuses any Type value `datagram_type_is_valid` rejects before reading
    /// anything after it, for the reason [`SubgroupHeader::decode`] gives: the
    /// Type is what names the layout of everything behind it. Which refusal it
    /// is comes from `datagram_type_error`, and a Type spelled in more than
    /// one byte is refused first by `wide_type_refusal`, so a padding
    /// datagram can be told from an unassigned one.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        if let Some(err) = wide_type_refusal(buf, datagram_type_error)? {
            return Err(err);
        }
        let raw = buf.get_u8() as u64;
        let datagram_type = raw as u8;

        if !datagram_type_is_valid(raw) {
            return Err(datagram_type_error(raw));
        }

        let track_alias = VarInt::decode_moqt::<Wire>(buf)?;
        let group_id = VarInt::decode_moqt::<Wire>(buf)?;

        let object_id = if datagram_type & DATAGRAM_ZERO_OBJECT_ID_BIT != 0 {
            VarInt::from_usize(0)
        } else {
            VarInt::decode_moqt::<Wire>(buf)?
        };

        let publisher_priority = if datagram_type & DATAGRAM_DEFAULT_PRIORITY_BIT == 0 {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        } else {
            None
        };

        let properties = if datagram_type & DATAGRAM_PROPERTIES_BIT != 0 {
            let props_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
            crate::types::read_bytes(buf, props_len)?
        } else {
            Vec::new()
        };

        let object_status = if datagram_type & DATAGRAM_STATUS_BIT != 0 {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            let status = buf.get_u8();
            Some(decoded_status(status as u64)?)
        } else {
            None
        };

        // Two rules of draft-18 Section 11.3.1 reach the properties block just
        // read, and neither is applied here — [`Self::properties_permitted`]
        // and [`Self::properties_block_well_formed`] report them instead, and
        // [`Self::encode_checked`] refuses to write either shape:
        //
        //   - "If an endpoint receives a datagram with the PROPERTIES bit set
        //     and an Properties Length of 0, it MUST close the session with a
        //     PROTOCOL_VIOLATION."
        //   - "If an Object Datagram includes both the STATUS bit and
        //     PROPERTIES bit, and the Object Status is not Normal (0x0), the
        //     endpoint MUST close the session with a PROTOCOL_VIOLATION,
        //     because only Normal Objects can have Properties."
        //
        // Both describe a datagram that is well framed and non-conforming: the
        // fields are all where the layout puts them and every one of them
        // parses, so a decoder can read the datagram back exactly as it
        // arrived. Refusing here would leave this module unable to reproduce a
        // capture containing one, and both rules address an endpoint receiving
        // such a datagram, so the endpoint is where they are enforced.
        //
        // The Type rules above are the contrast, and the contrast is what
        // decides it: an invalid Type names no layout at all, so reading on
        // invents the fields behind it rather than reporting them.

        Ok(DatagramHeader {
            datagram_type,
            track_alias,
            group_id,
            object_id,
            publisher_priority,
            properties,
            object_status,
        })
    }

    /// Decode one whole datagram: the header, then the payload that runs to the
    /// end of `buf`.
    ///
    /// `buf` must hold exactly one transport datagram and nothing else, since
    /// that boundary is the only thing that delimits the payload — draft-18
    /// Section 11.3.1: "There is no explicit length field for the Object
    /// Payload; the entirety of the transport datagram following the Object
    /// header contains the payload."
    ///
    /// Which is why the refusal lives here and not in [`Self::decode`]. A
    /// datagram whose type sets the STATUS bit has no payload at all — the same
    /// section: "When set to 1, the Object Status field is present and there is
    /// no Object Payload" — so trailing bytes after its status are not a short
    /// payload or an odd one, they are bytes the frame does not define. A
    /// decoder that stops at the header cannot see them, and a caller that
    /// treats whatever is left as the payload hands the application content the
    /// publisher never framed as content. That is the case this refuses.
    ///
    /// The same refusal covers a status the draft forbids a payload to: an
    /// object marked End of Group or End of Track may not carry one, per
    /// Section 11.2.1.1's "Any object with a status code other than zero MUST
    /// have an empty payload".
    ///
    /// Errors with [`CodecError::PayloadNotPermitted`] when bytes remain and
    /// the header forbids them, naming which of the two rules refused them.
    ///
    /// # The two Properties rules are enforced here too
    ///
    /// Section 11.3.1 states them of a receiving endpoint, and this is the
    /// endpoint's read:
    ///
    /// * "If an endpoint receives a datagram with the PROPERTIES bit set and an
    ///   Properties Length of 0, it MUST close the session with a
    ///   PROTOCOL_VIOLATION." The bit and a zero length are two ways to spell
    ///   *no properties* and a datagram may use only the first, because a
    ///   datagram with none has a Type that says so and the block costs bytes
    ///   the Type already saved. A subgroup stream says the opposite in
    ///   Section 11.4.2 — there the PROPERTIES bit is fixed for the whole stream,
    ///   so an object with no properties has nowhere else to say so and a
    ///   zero-length block is the required spelling.
    /// * "If an Object Datagram includes both the STATUS bit and PROPERTIES
    ///   bit, and the Object Status is not Normal (0x0), the endpoint MUST close
    ///   the session with a PROTOCOL_VIOLATION, because only Normal Objects can
    ///   have Properties."
    ///
    /// Both errors are [`CodecError::InvalidField`].
    ///
    /// [`Self::decode`] does **not** apply them, and the split is deliberate.
    /// Both describe a datagram that is well framed and non-conforming: every
    /// field is where the layout puts it and every one of them parses, so the
    /// header reads back exactly as it arrived and a tool reproducing a capture
    /// can re-emit it. What it may not do is hand such a datagram to an
    /// application as an ordinary Object, which is what this entry point would
    /// be doing. [`Self::properties_block_well_formed`] and
    /// [`Self::properties_permitted`] report the two for a caller that wants
    /// the header without the judgement, and [`Self::encode_checked`] refuses
    /// to write either shape.
    pub fn decode_object(buf: &mut impl Buf) -> Result<(Self, Vec<u8>), CodecError> {
        let header = Self::decode(buf)?;
        if !header.properties_block_well_formed() || !header.properties_permitted() {
            return Err(CodecError::InvalidField);
        }
        let payload = crate::types::read_bytes(buf, buf.remaining())?;
        if !payload.is_empty() && !header.permits_payload() {
            return Err(CodecError::PayloadNotPermitted {
                status: header.status().as_u64(),
                len: payload.len(),
                detail: if header.has_status() {
                    "its type states a status in place of a payload"
                } else {
                    "its status is registered as forbidding one"
                },
            });
        }
        Ok((header, payload))
    }

    /// Serialize the header, refusing a status the framing cannot carry.
    ///
    /// A datagram states a status only when its type byte sets the STATUS bit
    /// (0x20). With the bit clear there is no status field on the wire, so an
    /// `object_status` of anything but [`ObjectStatus::Normal`] has nowhere to
    /// go: [`Self::encode`] drops it, and the datagram parses back as an
    /// ordinary payload object. An End of Group marker written that way does
    /// not arrive late or malformed — it does not arrive at all, and the
    /// receiver sees a normal object in its place.
    ///
    /// Draft-18 Section 11.3.1 puts the framing side plainly — "The STATUS bit
    /// (0x20) indicates whether the datagram contains an Object Status or
    /// Object Payload" — and Section 11.2.1.1 the conformance side: "Any object
    /// with a status code other than zero MUST have an empty payload." Between
    /// them there is no datagram that carries a non-zero status and a payload,
    /// so the pair being refused here is not one this encoder merely declines
    /// to spell.
    ///
    /// [`ObjectStatus::Normal`] with the bit clear is not that case and is
    /// accepted. It is the status the encoding elides for every datagram that
    /// carries a payload, so stating it asks for exactly the bytes leaving it
    /// out asks for, and nothing is lost.
    ///
    /// A type value Section 11.3.1 lists as invalid is refused here too, on the
    /// same grounds: a receiver that follows the draft answers one with a
    /// PROTOCOL_VIOLATION, so writing it costs the session and not merely the
    /// datagram. The accepted set is the one [`Self::decode`] accepts.
    ///
    /// Errors with [`CodecError::InvalidField`] on either, before any byte is
    /// written, so a refused header leaves `buf` untouched. The status half is
    /// the datagram counterpart of the rule
    /// [`SubgroupObjectReader::write_object`] applies on a subgroup stream,
    /// where the status and the payload share a wire position.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        if !datagram_type_is_valid(self.datagram_type as u64) {
            return Err(datagram_type_error(self.datagram_type as u64));
        }
        if !self.has_status() && matches!(self.object_status, Some(s) if s != ObjectStatus::Normal)
        {
            return Err(CodecError::InvalidField);
        }
        // The two properties rules of Section 11.3.1. [`Self::decode`] reports
        // both rather than refusing them, because the datagrams they describe
        // are well framed and a codec that could not read one could not
        // reproduce a capture containing it. Writing one is the other
        // direction and has no such excuse: a conforming peer answers either
        // with a PROTOCOL_VIOLATION, so emitting one costs the session and not
        // merely the datagram.
        if !self.properties_block_well_formed() || !self.properties_permitted() {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
    }

    /// Serialize the header exactly as its type byte describes it.
    ///
    /// Every field the type byte announces is written, in the order
    /// [`Self::decode`] reads them, so the bytes this produces always parse
    /// back. The properties block in particular has to be written here: it
    /// sits ahead of the status field, and a datagram that skipped it would
    /// offer the status byte where the decoder reads the block's length.
    ///
    /// The type byte is taken as the authority on framing, which is what makes
    /// this infallible — and what makes it lossy when the struct disagrees with
    /// itself. An `object_status` set while the type byte leaves the STATUS bit
    /// clear is discarded here without a word. Prefer [`Self::encode_checked`],
    /// which refuses that combination instead of resolving it.
    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.datagram_type);
        self.track_alias.encode_moqt::<Wire>(buf);
        self.group_id.encode_moqt::<Wire>(buf);

        if self.datagram_type & DATAGRAM_ZERO_OBJECT_ID_BIT == 0 {
            self.object_id.encode_moqt::<Wire>(buf);
        }

        if self.datagram_type & DATAGRAM_DEFAULT_PRIORITY_BIT == 0 {
            buf.put_u8(self.publisher_priority.unwrap_or(128));
        }

        if self.datagram_type & DATAGRAM_PROPERTIES_BIT != 0 {
            VarInt::from_usize(self.properties.len()).encode_moqt::<Wire>(buf);
            buf.put_slice(&self.properties);
        }

        if self.datagram_type & DATAGRAM_STATUS_BIT != 0 {
            buf.put_u8(self.object_status.unwrap_or(ObjectStatus::Normal).as_u8());
        }
    }

    pub fn is_end_of_group(&self) -> bool {
        self.datagram_type & DATAGRAM_END_OF_GROUP_BIT != 0
    }

    pub fn has_status(&self) -> bool {
        self.datagram_type & DATAGRAM_STATUS_BIT != 0
    }

    /// `true` when the type byte sets the PROPERTIES bit (0x01), which is what
    /// puts the properties block on the wire.
    ///
    /// Reports the framing, not the contents. A decoded datagram with this set
    /// always has a non-empty [`Self::properties`], because [`Self::decode`]
    /// refuses a zero-length block; a header built by hand can hold the two
    /// apart, and [`Self::encode_checked`] is what refuses that.
    pub fn has_properties(&self) -> bool {
        self.datagram_type & DATAGRAM_PROPERTIES_BIT != 0
    }

    /// The object's status, with the one the encoding elides filled in.
    ///
    /// A datagram states a status only when its type sets the STATUS bit, and
    /// such a datagram has no payload. One without the bit is all payload, and
    /// the status of an object that carries a payload is
    /// [`ObjectStatus::Normal`] — draft-18 Section 11.2.1.1: "Any object with a
    /// status code other than zero MUST have an empty payload."
    pub fn status(&self) -> ObjectStatus {
        self.object_status.unwrap_or(ObjectStatus::Normal)
    }

    /// Whether this datagram's status is allowed to carry the properties it
    /// has.
    ///
    /// The same rule the subgroup form obeys. Draft-18 Section 11.3.1 builds
    /// the datagram's Properties field out of "the Object Properties structure
    /// defined in Section 11.2.1.2", and that section is where the general rule
    /// sits: "If an endpoint receives properties on an Object with status that
    /// is not Normal, it MUST close the session with a PROTOCOL_VIOLATION."
    /// Section 11.3.1 then states it again for this carrier in terms of the two
    /// bits, which is why [`Self::decode`] refuses the shape rather than merely
    /// reporting it — see [`SubgroupObject::properties_permitted`] for why the
    /// subgroup carrier is the other way round.
    pub fn properties_permitted(&self) -> bool {
        self.properties.is_empty() || self.status() == ObjectStatus::Normal
    }

    /// Whether the properties block is framed the way a datagram may frame it.
    ///
    /// Draft-18 Section 11.3.1: "If an endpoint receives a datagram with the
    /// PROPERTIES bit set and an Properties Length of 0, it MUST close the
    /// session with a PROTOCOL_VIOLATION."
    ///
    /// The bit and a zero length are two ways to spell "no properties", and on
    /// a datagram they are not interchangeable: a datagram with none has a type
    /// byte that says so, and the block costs bytes the type byte already
    /// saved. This rule is the datagram's alone. A subgroup stream says the
    /// opposite in Section 11.4.2 — "Objects with no properties set Properties
    /// Length to 0" — because there the PROPERTIES bit is fixed for the whole
    /// stream, so an object with no properties has nowhere else to say so and a
    /// zero-length block is the required spelling rather than a violation.
    ///
    /// The mirror case is not a wire state but is a state this struct can hold:
    /// properties with the bit clear. [`Self::encode`] drops them without a
    /// word, so this reports that too, and [`Self::encode_checked`] refuses
    /// both.
    pub fn properties_block_well_formed(&self) -> bool {
        self.has_properties() != self.properties.is_empty()
    }

    /// Whether the bytes after this datagram's header are allowed to exist.
    ///
    /// Draft-18 Section 11.2.1.1: "Any object with a status code other than
    /// zero MUST have an empty payload." Section 11.3.1 states the framing
    /// side of the same rule: "The STATUS bit (0x20) indicates whether the
    /// datagram contains an Object Status or Object Payload. When set to 1, the
    /// Object Status field is present and there is no Object Payload."
    ///
    /// Both halves of the rule are here. The framing half comes first and is
    /// the stronger one: with the STATUS bit set there is no Object Payload
    /// field at all, so no status — Normal included — makes trailing bytes
    /// part of the object. Answering from the status alone would report that a
    /// status datagram carrying Normal may be followed by a payload, and the
    /// bytes behind it would reach the application as one.
    ///
    /// The status half then covers the header that states a status its type
    /// byte gives no room for: End of Group under a type byte with the STATUS
    /// bit clear permits no payload either, which is why
    /// [`Self::encode_checked`] refuses to write that pair rather than
    /// silently dropping the status.
    ///
    /// This is the one place the blanket status-and-payload rule is not already
    /// satisfied by the framing. On a subgroup stream the status and the payload
    /// share a wire position, so no frame can state both; a datagram's payload is
    /// whatever follows the header to the end of the transport datagram, which
    /// [`Self::decode`] never sees and [`Self::decode_object`] does.
    pub fn permits_payload(&self) -> bool {
        if self.has_status() {
            return false;
        }
        match self.object_status {
            None => true,
            Some(status) => status == ObjectStatus::Normal,
        }
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
        let stream_type = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        if stream_type != FETCH_STREAM_TYPE {
            return Err(stream_type_error(stream_type));
        }
        let request_id = VarInt::decode_moqt::<Wire>(buf)?;
        Ok(FetchHeader { request_id })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(FETCH_STREAM_TYPE as usize).encode_moqt::<Wire>(buf);
        self.request_id.encode_moqt::<Wire>(buf);
    }
}

// ── Fetch objects ─────────────────────────────────────────────

/// Serialization Flags bits 0-1 (mask 0x03): how the Subgroup ID is encoded.
const FETCH_SUBGROUP_MODE_MASK: u64 = 0x03;
/// Mode 0x00: the Subgroup ID is zero.
const FETCH_SUBGROUP_MODE_ZERO: u64 = 0x00;
/// Mode 0x01: the Subgroup ID is the prior Object's.
const FETCH_SUBGROUP_MODE_PRIOR: u64 = 0x01;
/// Mode 0x02: the Subgroup ID is the prior Object's plus one.
const FETCH_SUBGROUP_MODE_PRIOR_PLUS_ONE: u64 = 0x02;
/// Mode 0x03: the Subgroup ID field is present.
const FETCH_SUBGROUP_MODE_PRESENT: u64 = 0x03;
/// Bit 0x04: the Object ID Delta field is present.
const FETCH_OBJECT_ID_DELTA_BIT: u64 = 0x04;
/// Bit 0x08: the Group ID Delta field is present.
const FETCH_GROUP_ID_DELTA_BIT: u64 = 0x08;
/// Bit 0x10: the Publisher Priority field is present.
const FETCH_PRIORITY_BIT: u64 = 0x10;
/// Bit 0x20: the Properties field is present.
const FETCH_PROPERTIES_BIT: u64 = 0x20;
/// Bit 0x40: the Object's forwarding preference is Datagram, so it has no
/// Subgroup ID and bits 0-1 are to be ignored.
const FETCH_DATAGRAM_BIT: u64 = 0x40;
/// The largest Serialization Flags value that is a set of flags. Draft-18
/// Section 11.4.4: "When less than 128, the bits represent flags described
/// below."
const FETCH_FLAGS_MAX: u64 = 0x7F;
/// Serialization Flags value 0x8C: End of Non-Existent Range.
const FETCH_END_OF_NON_EXISTENT_RANGE: u64 = 0x8C;
/// Serialization Flags value 0x10C: End of Unknown Range.
const FETCH_END_OF_UNKNOWN_RANGE: u64 = 0x10C;

/// Which End of Range a fetch frame marks, draft-18 Section 11.4.4.2.
///
/// "All Objects with Locations between the last serialized Object, if any, and
/// this Location, inclusive, either do not exist (when Serialization Flags is
/// 0x8C) or are unknown (0x10C)." The two are one frame shape with two
/// meanings, and only the publisher can tell them apart, so the distinction is
/// carried rather than collapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndOfRange {
    /// Serialization Flags 0x8C: the Objects in the range do not exist.
    NonExistent,
    /// Serialization Flags 0x10C: the Objects in the range have unknown status.
    Unknown,
}

/// The order a FETCH response's Groups arrive in, which decides how a Group ID
/// Delta is applied.
///
/// Draft-18 Section 11.4.4.1: "If the Group Order is Ascending, the Group ID is
/// the prior Object's Group ID plus the Group ID Delta + 1. If the Group Order
/// is Descending, the Group ID is the prior Object's Group ID minus the (Group
/// ID Delta + 1)."
///
/// The order is not on the data stream — it is settled by the control exchange
/// that opened the FETCH, whose GROUP_ORDER parameter (Section 10.2.8) spells
/// Ascending 0x1 and Descending 0x2 — so [`FetchObjectReader`] has to be told
/// which one it is reading. Getting it wrong does not fail to parse: it decodes
/// every Object under a Group ID that walks the wrong way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupOrder {
    /// Group IDs increase: a delta adds to the prior Group ID.
    Ascending,
    /// Group IDs decrease: a delta subtracts from the prior Group ID.
    Descending,
}

/// One frame on a draft-18 FETCH stream, exactly as it sits on the wire.
///
/// Draft-18 Section 11.4.4 gives the layout as
///
/// ```text
/// {
///   Serialization Flags (vi64),
///   [Group ID Delta (vi64),]
///   [Subgroup ID (vi64),]
///   [Object ID Delta (vi64),]
///   [Publisher Priority (8),]
///   [Properties (..),]
///   Object Payload Length (vi64),
///   [Object Payload (..),]
/// }
/// ```
///
/// Every optional field is present exactly when the Serialization Flags say so,
/// which is why they are `Option` here rather than resolved values: this type
/// holds what was written, not what it means. The Object's actual Group ID,
/// Subgroup ID, Object ID and Priority come from resolving these against the
/// frame before them, which is [`FetchObjectReader`]'s job — a header on its
/// own cannot say, because most of its fields are differences from an Object it
/// does not have.
///
/// Unlike a subgroup object, a fetch object carries no Object Status:
/// Section 11.2.1.1 says the field "is only present in objects that are
/// delivered via a SUBSCRIPTION, and is absent in Objects delivered via a
/// FETCH". A zero Object Payload Length here is an empty payload and nothing
/// more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObjectHeader {
    /// The Serialization Flags varint, verbatim. Below 128 it is a set of
    /// flags; 0x8C and 0x10C are the two End of Range markers; the decoder
    /// refuses everything else.
    pub serialization_flags: u64,
    /// The Group ID Delta field, or — on an End of Range marker — the absolute
    /// Group ID that marker names.
    pub group_id_delta: Option<VarInt>,
    /// The explicit Subgroup ID field, present only in subgroup mode 0b11 with
    /// the Datagram bit clear.
    pub subgroup_id: Option<VarInt>,
    /// The Object ID Delta field, or — on an End of Range marker — the absolute
    /// Object ID that marker names.
    pub object_id_delta: Option<VarInt>,
    /// The Publisher Priority octet, present only when bit 0x10 is set.
    pub publisher_priority: Option<u8>,
    /// Raw properties bytes, excluding the byte-length prefix that precedes
    /// them on the wire. Empty when bit 0x20 is clear, and re-emitted verbatim
    /// by [`Self::encode`].
    pub properties: Vec<u8>,
    /// Object Payload Length. The payload itself follows the header and is not
    /// held here, so that a caller forwarding bytes never has to copy them.
    pub payload_length: VarInt,
}

impl FetchObjectHeader {
    /// Which End of Range this frame marks, or `None` when it is an Object.
    ///
    /// Draft-18 Section 11.4.4, Table 7 assigns 0x8C and 0x10C, both above the
    /// 128 below which the field is a set of flags, so no flag combination can
    /// be mistaken for a marker.
    pub fn end_of_range(&self) -> Option<EndOfRange> {
        match self.serialization_flags {
            FETCH_END_OF_NON_EXISTENT_RANGE => Some(EndOfRange::NonExistent),
            FETCH_END_OF_UNKNOWN_RANGE => Some(EndOfRange::Unknown),
            _ => None,
        }
    }

    /// `true` when bit 0x40 marks this Object's forwarding preference as
    /// Datagram, so it has no Subgroup ID.
    ///
    /// Draft-18 Section 11.4.4.1: "When encoding an Object with a Forwarding
    /// Preference of 'Datagram' ... the object has no Subgroup ID. The
    /// publisher MUST SET bit 0x40 to '1'. When 0x40 is set, it SHOULD set the
    /// two least significant bits to zero and the subscriber MUST ignore the
    /// bits." Ignoring them is what this predicate is for: with the bit set,
    /// the two-bit mode field says nothing, not even when it reads 0b11, so no
    /// Subgroup ID is on the wire to read.
    pub fn is_datagram(&self) -> bool {
        self.end_of_range().is_none() && self.serialization_flags & FETCH_DATAGRAM_BIT != 0
    }

    /// The Subgroup ID mode, bits 0-1, for an Object that has one.
    ///
    /// `None` for an End of Range marker, which carries no Subgroup ID field,
    /// and for an Object whose Datagram bit is set, whose two low bits the
    /// draft says to ignore.
    fn subgroup_mode(&self) -> Option<u64> {
        if self.end_of_range().is_some() || self.is_datagram() {
            return None;
        }
        Some(self.serialization_flags & FETCH_SUBGROUP_MODE_MASK)
    }

    /// Decode one frame, without its payload.
    ///
    /// Errors with [`CodecError::InvalidField`] on a Serialization Flags value
    /// that is neither a set of flags nor one of the two End of Range markers.
    /// Draft-18 Section 11.4.4 lists the two additional values and then says of
    /// the field: "Any other value is a PROTOCOL_VIOLATION." Nothing after the
    /// flags can be read without them, since they are what says which fields
    /// are there.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let serialization_flags = VarInt::decode_moqt::<Wire>(buf)?.into_inner();

        match serialization_flags {
            // Section 11.4.4.2: "the Group ID and Object ID fields are
            // present. Subgroup ID, Priority and Properties are not present."
            // The Object Payload Length field is not named as absent and so
            // stays, as the corpus of draft-18 fetch vectors also has it.
            FETCH_END_OF_NON_EXISTENT_RANGE | FETCH_END_OF_UNKNOWN_RANGE => {
                let group_id = VarInt::decode_moqt::<Wire>(buf)?;
                let object_id = VarInt::decode_moqt::<Wire>(buf)?;
                let payload_length = VarInt::decode_moqt::<Wire>(buf)?;
                Ok(FetchObjectHeader {
                    serialization_flags,
                    group_id_delta: Some(group_id),
                    subgroup_id: None,
                    object_id_delta: Some(object_id),
                    publisher_priority: None,
                    properties: Vec::new(),
                    payload_length,
                })
            }
            flags if flags <= FETCH_FLAGS_MAX => {
                let group_id_delta = if flags & FETCH_GROUP_ID_DELTA_BIT != 0 {
                    Some(VarInt::decode_moqt::<Wire>(buf)?)
                } else {
                    None
                };

                // The Datagram bit suppresses the field even in mode 0b11:
                // an Object with no Subgroup ID has none to write, and the
                // draft tells the subscriber to ignore the mode bits.
                let explicit_subgroup = flags & FETCH_DATAGRAM_BIT == 0
                    && flags & FETCH_SUBGROUP_MODE_MASK == FETCH_SUBGROUP_MODE_PRESENT;
                let subgroup_id =
                    if explicit_subgroup { Some(VarInt::decode_moqt::<Wire>(buf)?) } else { None };

                let object_id_delta = if flags & FETCH_OBJECT_ID_DELTA_BIT != 0 {
                    Some(VarInt::decode_moqt::<Wire>(buf)?)
                } else {
                    None
                };

                let publisher_priority = if flags & FETCH_PRIORITY_BIT != 0 {
                    if buf.remaining() < 1 {
                        return Err(CodecError::UnexpectedEnd);
                    }
                    Some(buf.get_u8())
                } else {
                    None
                };

                let properties = if flags & FETCH_PROPERTIES_BIT != 0 {
                    let len = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
                    let len = usize::try_from(len).map_err(|_| CodecError::UnexpectedEnd)?;
                    crate::types::read_bytes(buf, len)?
                } else {
                    Vec::new()
                };

                let payload_length = VarInt::decode_moqt::<Wire>(buf)?;

                Ok(FetchObjectHeader {
                    serialization_flags,
                    group_id_delta,
                    subgroup_id,
                    object_id_delta,
                    publisher_priority,
                    properties,
                    payload_length,
                })
            }
            _ => Err(CodecError::InvalidField),
        }
    }

    /// Serialize the frame, refusing one that does not describe itself.
    ///
    /// The Serialization Flags are the authority on which fields are on the
    /// wire, so a field the flags announce and the struct does not hold has no
    /// bytes to write, and a field the struct holds and the flags do not
    /// announce has nowhere to go. Either way the frame [`Self::decode`] would
    /// read back is not the one that was handed over, and no caller could
    /// repair it by appending bytes — the flags are already written.
    ///
    /// Errors with [`CodecError::InvalidField`] in those cases and on a flags
    /// value the draft does not define, before any byte is written, so a
    /// refused frame leaves `buf` untouched rather than half a frame the next
    /// read would run into. This is the fetch counterpart of the rule
    /// [`SubgroupObjectReader::write_object`] applies to a declared payload
    /// length.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let flags = self.serialization_flags;
        let marker = self.end_of_range().is_some();

        if !marker && flags > FETCH_FLAGS_MAX {
            return Err(CodecError::InvalidField);
        }

        let wants_group = marker || flags & FETCH_GROUP_ID_DELTA_BIT != 0;
        let wants_object = marker || flags & FETCH_OBJECT_ID_DELTA_BIT != 0;
        let wants_subgroup = self.subgroup_mode() == Some(FETCH_SUBGROUP_MODE_PRESENT);
        let wants_priority = !marker && flags & FETCH_PRIORITY_BIT != 0;
        let wants_properties = !marker && flags & FETCH_PROPERTIES_BIT != 0;

        if wants_group != self.group_id_delta.is_some()
            || wants_object != self.object_id_delta.is_some()
            || wants_subgroup != self.subgroup_id.is_some()
            || wants_priority != self.publisher_priority.is_some()
            || (!wants_properties && !self.properties.is_empty())
        {
            return Err(CodecError::InvalidField);
        }

        VarInt::from_u64_moqt(flags).encode_moqt::<Wire>(buf);
        if let Some(group_id_delta) = self.group_id_delta {
            group_id_delta.encode_moqt::<Wire>(buf);
        }
        if let Some(subgroup_id) = self.subgroup_id {
            subgroup_id.encode_moqt::<Wire>(buf);
        }
        if let Some(object_id_delta) = self.object_id_delta {
            object_id_delta.encode_moqt::<Wire>(buf);
        }
        if let Some(priority) = self.publisher_priority {
            buf.put_u8(priority);
        }
        if wants_properties {
            VarInt::from_usize(self.properties.len()).encode_moqt::<Wire>(buf);
            buf.put_slice(&self.properties);
        }
        self.payload_length.encode_moqt::<Wire>(buf);
        Ok(())
    }
}

/// One frame from a FETCH stream with its delta-encoded fields resolved.
///
/// The header is kept alongside the resolved values so that a caller can
/// forward the frame's bytes unchanged while acting on what they mean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObject {
    /// The frame as it appeared on the wire.
    pub header: FetchObjectHeader,
    /// Resolved absolute Group ID. On an End of Range marker, the Group ID of
    /// the Location the marker names.
    pub group_id: u64,
    /// Resolved Subgroup ID. `None` for an End of Range marker, which has
    /// none, and for an Object whose forwarding preference is Datagram.
    pub subgroup_id: Option<u64>,
    /// Resolved absolute Object ID. On an End of Range marker, the Object ID of
    /// the Location the marker names.
    pub object_id: u64,
    /// The Publisher Priority in force for this frame, whether this frame wrote
    /// it or an earlier one did, and `None` while no frame has written one.
    ///
    /// An End of Range marker carries no Priority field of its own, so what it
    /// reports is the one still in force from the last Object before it —
    /// Section 11.4.4.2: "Prior Priority: The Priority from the last actual
    /// Object before the End of Range indicator."
    ///
    /// The fallback for a subscription that never stated a priority is left to
    /// the caller rather than substituted here, so that "no frame has said"
    /// stays distinguishable from "a frame said 128".
    pub publisher_priority: Option<u8>,
}

/// Resolves the delta-encoded fields of the frames on one FETCH stream.
///
/// Draft-18 Section 11.4.4.1 defines nearly every field of a fetch frame
/// against "the prior Object", so no frame after the first can be understood on
/// its own. This holds what the frames so far established, in the two parts the
/// draft keeps separate: Section 11.4.4.2 says that after an End of Range
/// marker the prior Group ID and Object ID are the marker's, while the prior
/// Subgroup ID and Priority are still "from the last actual Object before the
/// End of Range indicator".
///
/// Every rule the section answers with a PROTOCOL_VIOLATION is refused here
/// with [`CodecError::InvalidField`]: a first Object that references fields no
/// prior Object established, a Subgroup ID or Priority inherited when there is
/// none to inherit, and an arithmetic result outside the 64-bit range.
#[derive(Debug, Clone)]
pub struct FetchObjectReader {
    group_order: GroupOrder,
    /// Group ID and Object ID of the last frame, marker or Object.
    prior_location: Option<(u64, u64)>,
    /// Subgroup ID of the last actual Object that had one.
    prior_subgroup_id: Option<u64>,
    /// Publisher Priority of the last actual Object.
    prior_publisher_priority: Option<u8>,
}

impl FetchObjectReader {
    /// A reader for a stream whose Groups arrive in `group_order`.
    pub fn new(group_order: GroupOrder) -> Self {
        Self {
            group_order,
            prior_location: None,
            prior_subgroup_id: None,
            prior_publisher_priority: None,
        }
    }

    /// Decode the next frame's header and resolve its fields.
    ///
    /// Consumes the header only. The Object Payload is
    /// `header.payload_length` bytes and stays in `buf`, so a caller that
    /// forwards payloads never copies them and one that ignores them can skip.
    ///
    /// Errors with [`CodecError::InvalidField`] on every rule
    /// Section 11.4.4.1 states:
    ///
    /// - "The first Object MUST include a Group ID Delta and Object ID Delta,
    ///   and these values are the absolute Group ID and Object ID. If the first
    ///   Object in the FETCH response uses a flag that references fields in the
    ///   prior Object, the Subscriber MUST close the session with a
    ///   PROTOCOL_VIOLATION." Each such flag is refused where it is read, so
    ///   the reason survives: a missing delta, an inherited Priority and an
    ///   inherited Subgroup ID are three different frames, all of them
    ///   referencing an Object that does not exist.
    /// - "If the computed Group ID would be less than 0 or greater than
    ///   2^64-1, the Subscriber MUST close the Session with error
    ///   'PROTOCOL_VIOLATION'" — the descending and ascending ends of the same
    ///   rule.
    /// - "If the computed Object ID would be greater than 2^64-1, the
    ///   Subscriber MUST close the Session with error 'PROTOCOL_VIOLATION'."
    pub fn read_object_header(&mut self, buf: &mut impl Buf) -> Result<FetchObject, CodecError> {
        let header = FetchObjectHeader::decode(buf)?;

        // An End of Range marker states a Location outright and inherits
        // nothing, so it is resolved before any of the prior-Object rules.
        if header.end_of_range().is_some() {
            let group_id = header.group_id_delta.ok_or(CodecError::InvalidField)?.into_inner();
            let object_id = header.object_id_delta.ok_or(CodecError::InvalidField)?.into_inner();
            self.prior_location = Some((group_id, object_id));
            let publisher_priority = self.prior_publisher_priority;
            return Ok(FetchObject {
                header,
                group_id,
                subgroup_id: None,
                object_id,
                publisher_priority,
            });
        }

        let group_id = match (self.prior_location, header.group_id_delta) {
            (None, Some(delta)) => delta.into_inner(),
            // No prior Object, and the frame asks for its Group ID.
            (None, None) => return Err(CodecError::InvalidField),
            (Some((prior_group, _)), None) => prior_group,
            (Some((prior_group, _)), Some(delta)) => {
                let delta = delta.into_inner();
                match self.group_order {
                    GroupOrder::Ascending => prior_group
                        .checked_add(delta)
                        .and_then(|v| v.checked_add(1))
                        .ok_or(CodecError::InvalidField)?,
                    GroupOrder::Descending => prior_group
                        .checked_sub(delta)
                        .and_then(|v| v.checked_sub(1))
                        .ok_or(CodecError::InvalidField)?,
                }
            }
        };

        let object_id =
            match (self.prior_location, header.group_id_delta.is_some(), header.object_id_delta) {
                // "When the Group ID Delta field is present, the Object ID is
                // the value of Object ID Delta if present" — an absolute value,
                // as it is for the first Object on the stream.
                (_, true, Some(delta)) => delta.into_inner(),
                // "When the Group ID Delta field is not present, the Object ID
                // is the prior Object's ID plus the Object ID Delta if
                // present."
                (Some((_, prior_object)), false, Some(delta)) => {
                    prior_object.checked_add(delta.into_inner()).ok_or(CodecError::InvalidField)?
                }
                // "If Object ID Delta is not present, the Object ID is the
                // prior Object's ID plus one, regardless of which group it
                // belongs to" — which is why a new Group with no Object ID
                // Delta does not restart at zero.
                (Some((_, prior_object)), _, None) => {
                    prior_object.checked_add(1).ok_or(CodecError::InvalidField)?
                }
                // No prior Object, and the frame asks for its Object ID.
                (None, _, _) => return Err(CodecError::InvalidField),
            };

        let subgroup_id = match header.subgroup_mode() {
            None => None,
            Some(FETCH_SUBGROUP_MODE_ZERO) => Some(0),
            Some(FETCH_SUBGROUP_MODE_PRIOR) => {
                Some(self.prior_subgroup_id.ok_or(CodecError::InvalidField)?)
            }
            Some(FETCH_SUBGROUP_MODE_PRIOR_PLUS_ONE) => Some(
                self.prior_subgroup_id
                    .ok_or(CodecError::InvalidField)?
                    .checked_add(1)
                    .ok_or(CodecError::InvalidField)?,
            ),
            // Mode 0b11, the only value left: the field is on the wire.
            Some(_) => Some(header.subgroup_id.ok_or(CodecError::InvalidField)?.into_inner()),
        };

        let publisher_priority = match header.publisher_priority {
            Some(priority) => priority,
            None => self.prior_publisher_priority.ok_or(CodecError::InvalidField)?,
        };

        self.prior_location = Some((group_id, object_id));
        // An Object with a Datagram forwarding preference has no Subgroup ID,
        // so it leaves the prior one standing rather than clearing it: the
        // Object after it inherits from the last Object that had one.
        if let Some(subgroup_id) = subgroup_id {
            self.prior_subgroup_id = Some(subgroup_id);
        }
        self.prior_publisher_priority = Some(publisher_priority);

        Ok(FetchObject {
            header,
            group_id,
            subgroup_id,
            object_id,
            publisher_priority: Some(publisher_priority),
        })
    }
}

/// Re-encodes resolved fetch frames onto one FETCH stream.
///
/// The exact inverse of [`FetchObjectReader`], and it exists for one caller:
/// something that has read a stream and is writing a different stream from the
/// same frames. Removing a frame changes what the frames after it are encoded
/// *against*, and draft-18 Section 11.4.4.1 defines nearly every field against
/// the prior Object, so the survivor that follows a removed run cannot keep its
/// original bytes. What has to change is not one field: an Object that carried
/// no Group ID Delta because it shared its predecessor's group needs one once
/// that predecessor is gone, so a field appears and a flag bit with it.
///
/// # Why this is not a general encoder
///
/// Every frame it writes came off a stream, so the caller already holds the
/// frame's own [`FetchObjectHeader`] alongside the resolved values. That header
/// is used as the preference: wherever the original shape still encodes the
/// same meaning against the new predecessor it is kept, so a stream with
/// nothing removed from it is reproduced byte for byte. Only where the original
/// shape would now decode to something else is a different one chosen.
///
/// # What it refuses
///
/// [`CodecError::InvalidField`] where no encoding exists rather than picking
/// one: a Group ID that moves against the FETCH's Group Order, an Object ID
/// that does not advance, an Object with neither a Subgroup ID nor the Datagram
/// bit, and the arithmetic overflows.
#[derive(Debug, Clone)]
pub struct FetchObjectWriter {
    group_order: GroupOrder,
    /// Group ID and Object ID of the last frame written, marker or Object.
    prior_location: Option<(u64, u64)>,
    /// Subgroup ID of the last actual Object written that had one.
    prior_subgroup_id: Option<u64>,
    /// Publisher Priority of the last actual Object written.
    prior_publisher_priority: Option<u8>,
}

impl FetchObjectWriter {
    /// A writer for a stream whose Groups are being written in `group_order`.
    ///
    /// The order has to match the one the FETCH was opened with, for the same
    /// reason [`FetchObjectReader::new`] takes it: it decides whether a Group
    /// ID Delta adds or subtracts, and it is not on the data stream.
    pub fn new(group_order: GroupOrder) -> Self {
        Self {
            group_order,
            prior_location: None,
            prior_subgroup_id: None,
            prior_publisher_priority: None,
        }
    }

    /// The header that encodes `frame` against everything written so far.
    ///
    /// Does not advance the writer — [`Self::write_object_header`] is the call
    /// that does both.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] for a frame that cannot be encoded against
    /// the current predecessor; see the type's own documentation for the list.
    pub fn header_for(&self, frame: &FetchObject) -> Result<FetchObjectHeader, CodecError> {
        let original = &frame.header;

        // An End of Range marker states its Location outright and inherits
        // nothing, so its two fields are the same whatever precedes it.
        if original.end_of_range().is_some() {
            return Ok(FetchObjectHeader {
                serialization_flags: original.serialization_flags,
                group_id_delta: Some(VarInt::from_u64(frame.group_id)?),
                subgroup_id: None,
                object_id_delta: Some(VarInt::from_u64(frame.object_id)?),
                publisher_priority: None,
                properties: Vec::new(),
                payload_length: original.payload_length,
            });
        }

        let (group_id_delta, object_id_delta) = self.identity_fields(frame, original)?;
        let (subgroup_mode, subgroup_id) = self.subgroup_field(frame, original)?;
        let publisher_priority = self.priority_field(frame, original)?;

        let mut flags = subgroup_mode;
        if original.serialization_flags & FETCH_DATAGRAM_BIT != 0 {
            flags |= FETCH_DATAGRAM_BIT;
        }
        if group_id_delta.is_some() {
            flags |= FETCH_GROUP_ID_DELTA_BIT;
        }
        if object_id_delta.is_some() {
            flags |= FETCH_OBJECT_ID_DELTA_BIT;
        }
        if publisher_priority.is_some() {
            flags |= FETCH_PRIORITY_BIT;
        }
        if original.serialization_flags & FETCH_PROPERTIES_BIT != 0 {
            flags |= FETCH_PROPERTIES_BIT;
        }

        Ok(FetchObjectHeader {
            serialization_flags: flags,
            group_id_delta,
            subgroup_id,
            object_id_delta,
            publisher_priority,
            properties: original.properties.clone(),
            payload_length: original.payload_length,
        })
    }

    /// The Group ID Delta and Object ID Delta fields, as this predecessor needs
    /// them.
    ///
    /// Presence is forced by the frame rather than chosen: a group that differs
    /// from the predecessor's has to be stated, and one that matches has to be
    /// left off, since a delta of zero means the next group along and not this
    /// one.
    fn identity_fields(
        &self,
        frame: &FetchObject,
        original: &FetchObjectHeader,
    ) -> Result<(Option<VarInt>, Option<VarInt>), CodecError> {
        let Some((prior_group, prior_object)) = self.prior_location else {
            // The first Object carries both deltas and they are absolute.
            return Ok((
                Some(VarInt::from_u64(frame.group_id)?),
                Some(VarInt::from_u64(frame.object_id)?),
            ));
        };

        if frame.group_id != prior_group {
            // A Group ID Delta moves the group by delta + 1, forwards under
            // Ascending and backwards under Descending, and when an Object ID
            // Delta accompanies it the Object ID is that delta outright rather
            // than an advance on the predecessor.
            let step = match self.group_order {
                GroupOrder::Ascending => frame.group_id.checked_sub(prior_group),
                GroupOrder::Descending => prior_group.checked_sub(frame.group_id),
            };
            let delta = step.and_then(|s| s.checked_sub(1)).ok_or(CodecError::InvalidField)?;

            // Omitting the Object ID Delta across a group boundary is legal and
            // is a byte shorter. Section 11.4.4.1: "If Object ID Delta is not
            // present, the Object ID is the prior Object's ID plus one,
            // REGARDLESS OF WHICH GROUP IT BELONGS TO." So an Object that
            // continues the numbering into a new group encodes without one --
            // the Object ID does not restart at the group boundary unless a
            // delta says so.
            //
            // Gated on the frame's own framing, like the same-group case below,
            // so re-emitting a stream reproduces the publisher's bytes instead
            // of silently rewriting the shorter form into the longer one. It
            // also keeps markers correct without a special case: a marker
            // always arrives with an Object ID Delta and never takes this
            // branch.
            if original.object_id_delta.is_none()
                && frame.object_id == prior_object.wrapping_add(1)
                && prior_object != u64::MAX
            {
                return Ok((Some(VarInt::from_u64(delta)?), None));
            }

            return Ok((Some(VarInt::from_u64(delta)?), Some(VarInt::from_u64(frame.object_id)?)));
        }

        // Same group. The Object ID is the predecessor's plus the delta, or
        // plus one when no delta is written, so an Object that does not advance
        // has no encoding at all.
        let advance = frame.object_id.checked_sub(prior_object).ok_or(CodecError::InvalidField)?;
        if advance == 0 {
            return Err(CodecError::InvalidField);
        }
        if advance == 1 && original.object_id_delta.is_none() {
            return Ok((None, None));
        }
        Ok((None, Some(VarInt::from_u64(advance)?)))
    }

    /// The Subgroup ID mode bits and the explicit field, if one is needed.
    ///
    /// The frame's own mode is tried first, so a run of Objects that inherited
    /// their Subgroup ID keeps inheriting it and its bytes do not move.
    fn subgroup_field(
        &self,
        frame: &FetchObject,
        original: &FetchObjectHeader,
    ) -> Result<(u64, Option<VarInt>), CodecError> {
        // With the Datagram bit set the two low bits say nothing and no field
        // is on the wire, so the frame's own bits are carried across untouched.
        if original.serialization_flags & FETCH_DATAGRAM_BIT != 0 {
            return Ok((original.serialization_flags & FETCH_SUBGROUP_MODE_MASK, None));
        }

        let subgroup_id = frame.subgroup_id.ok_or(CodecError::InvalidField)?;
        let inherits = self.prior_subgroup_id == Some(subgroup_id);
        let successor =
            self.prior_subgroup_id.is_some_and(|p| p.checked_add(1) == Some(subgroup_id));

        let kept = match original.serialization_flags & FETCH_SUBGROUP_MODE_MASK {
            FETCH_SUBGROUP_MODE_ZERO if subgroup_id == 0 => Some((FETCH_SUBGROUP_MODE_ZERO, None)),
            FETCH_SUBGROUP_MODE_PRIOR if inherits => Some((FETCH_SUBGROUP_MODE_PRIOR, None)),
            FETCH_SUBGROUP_MODE_PRIOR_PLUS_ONE if successor => {
                Some((FETCH_SUBGROUP_MODE_PRIOR_PLUS_ONE, None))
            }
            FETCH_SUBGROUP_MODE_PRESENT => Some((FETCH_SUBGROUP_MODE_PRESENT, Some(subgroup_id))),
            _ => None,
        };
        let (mode, explicit) = match kept {
            Some(pair) => pair,
            None if subgroup_id == 0 => (FETCH_SUBGROUP_MODE_ZERO, None),
            None if inherits => (FETCH_SUBGROUP_MODE_PRIOR, None),
            None if successor => (FETCH_SUBGROUP_MODE_PRIOR_PLUS_ONE, None),
            None => (FETCH_SUBGROUP_MODE_PRESENT, Some(subgroup_id)),
        };
        Ok((mode, explicit.map(VarInt::from_u64).transpose()?))
    }

    /// The Publisher Priority field, or `None` when the predecessor already
    /// carries it.
    fn priority_field(
        &self,
        frame: &FetchObject,
        original: &FetchObjectHeader,
    ) -> Result<Option<u8>, CodecError> {
        let priority = frame.publisher_priority.ok_or(CodecError::InvalidField)?;
        if original.publisher_priority.is_some() || self.prior_publisher_priority != Some(priority)
        {
            return Ok(Some(priority));
        }
        Ok(None)
    }

    /// Encode `frame` against everything written so far and advance.
    ///
    /// Writes the header only. The payload is `frame.header.payload_length`
    /// bytes and is the caller's to copy, unchanged.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] for a frame with no encoding against the
    /// current predecessor. The writer is left untouched when this happens.
    pub fn write_object_header(
        &mut self,
        frame: &FetchObject,
        out: &mut impl BufMut,
    ) -> Result<FetchObjectHeader, CodecError> {
        let header = self.header_for(frame)?;
        header.encode(out)?;
        self.advance(frame);
        Ok(header)
    }

    /// Record `frame` as the predecessor of whatever is written next.
    ///
    /// Public because a re-emitting caller has a second way of putting a frame
    /// on the wire: when the framing it arrived in still encodes the same
    /// meaning against the frame before it, its own bytes are forwarded
    /// untouched — no header is produced and nothing is copied. The writer
    /// still has to move, or the frame after it is encoded against a
    /// predecessor one frame stale.
    pub fn advance(&mut self, frame: &FetchObject) {
        self.prior_location = Some((frame.group_id, frame.object_id));
        // Mirrors the reader: a Datagram-forwarded Object leaves no Subgroup ID
        // behind, so the running one survives it.
        if let Some(subgroup_id) = frame.subgroup_id {
            self.prior_subgroup_id = Some(subgroup_id);
        }
        if frame.header.end_of_range().is_none() {
            if let Some(priority) = frame.publisher_priority {
                self.prior_publisher_priority = Some(priority);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonically encoded subgroup stream vectors from
    /// `test-vectors/transport/draft18/codec/data-streams/subgroup.json`.
    /// `subgroup-explicit-subgroup-id` is omitted: it encodes group_id 100 as a
    /// two-byte varint, which does not survive a minimal-width re-encode.
    const VECTORS: &[&str] = &[
        // subgroup-single-object
        "100100800004deadbeef",
        // subgroup-two-objects
        "100100800004deadbeef0002cafe",
        // subgroup-no-priority
        "3001000004deadbeef",
        // subgroup-with-extensions
        "11010080000004deadbeef",
        // subgroup-end-of-group
        "180105800004deadbeef",
        // subgroup-id-mode-01
        "120100800504deadbeef",
        // subgroup-with-object-properties
        "1101008000043c02020104deadbeef",
        // subgroup-object-status-end-of-group
        "100100800004deadbeef000003",
        // subgroup-object-status-end-of-track
        "10010080000004",
        // subgroup-properties-two-objects-empty
        "11010080000004deadbeef000002cafe",
        // subgroup-properties-two-objects-nonempty
        "1101008000023c0204deadbeef00023c0302cafe",
        // subgroup-properties-status-object
        "1101008000023c010003",
        // subgroup-first-object-bit
        "500100800004deadbeef",
        // subgroup-first-object-and-end-of-group
        "580102800002cafe",
    ];

    fn vi(v: u64) -> VarInt {
        VarInt::from_u64_moqt(v)
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Decode a whole subgroup stream: the header, then every object up to
    /// the end of the buffer.
    fn decode_all(bytes: &[u8]) -> (SubgroupHeader, Vec<SubgroupObject>) {
        let mut cursor = bytes;
        let header = SubgroupHeader::decode(&mut cursor)
            .unwrap_or_else(|e| panic!("header decode failed: {e:?}"));
        let mut reader = SubgroupObjectReader::new(&header);
        let mut objects = Vec::new();
        while cursor.has_remaining() {
            objects.push(
                reader
                    .read_object(&mut cursor)
                    .unwrap_or_else(|e| panic!("object {} decode failed: {e:?}", objects.len())),
            );
        }
        (header, objects)
    }

    fn encode_all(header: &SubgroupHeader, objects: &[SubgroupObject]) -> Vec<u8> {
        let mut buf = Vec::new();
        header.encode(&mut buf);
        let mut writer = SubgroupObjectReader::new(header);
        for o in objects {
            writer.write_object(o, &mut buf).unwrap_or_else(|e| panic!("write failed: {e:?}"));
        }
        buf
    }

    fn object(id: u64, extensions: Vec<u8>, payload: Vec<u8>) -> SubgroupObject {
        SubgroupObject {
            object_id: vi(id),
            extension_headers: extensions,
            payload_length: vi(payload.len() as u64),
            object_status: None,
            payload,
        }
    }

    // ── Object ID deltas ────────────────────────────────────

    #[test]
    fn two_objects_with_properties_have_distinct_ids() {
        // Vector `subgroup-properties-two-objects-empty`: two objects, each
        // carrying an empty properties block and a delta of 0. The delta is
        // biased by one whether or not the properties bit is set, so the IDs
        // are 0 and 1 — not 0 and 0.
        let bytes = hex("11010080000004deadbeef000002cafe");
        let (header, objects) = decode_all(&bytes);
        assert!(header.has_properties());
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].object_id.into_inner(), 0);
        assert_eq!(objects[1].object_id.into_inner(), 1);
        assert_eq!(objects[0].payload, hex("deadbeef"));
        assert_eq!(objects[1].payload, hex("cafe"));
        assert!(objects.iter().all(|o| o.extension_headers.is_empty()));
    }

    #[test]
    fn deltas_resolve_sparse_ids() {
        let header = SubgroupHeader::decode(&mut &hex("100100800004deadbeef")[..]).unwrap();
        let objects: Vec<_> =
            [3u64, 4, 40].iter().map(|&id| object(id, vec![], vec![0xAA, id as u8])).collect();
        let (_, decoded) = decode_all(&encode_all(&header, &objects));
        let ids: Vec<u64> = decoded.iter().map(|o| o.object_id.into_inner()).collect();
        assert_eq!(ids, vec![3, 4, 40]);
    }

    #[test]
    fn write_rejects_non_increasing_ids() {
        let header = SubgroupHeader::decode(&mut &hex("100100800004deadbeef")[..]).unwrap();
        let mut writer = SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        writer.write_object(&object(7, vec![], vec![0x01]), &mut buf).unwrap();
        for id in [7u64, 6, 0] {
            let err = writer.write_object(&object(id, vec![], vec![0x01]), &mut buf).unwrap_err();
            assert!(matches!(err, CodecError::InvalidField), "id {id} gave {err:?}");
        }
    }

    #[test]
    fn eliding_an_object_renumbers_its_successor() {
        let header = SubgroupHeader::decode(&mut &hex("100100800004deadbeef")[..]).unwrap();
        let all: Vec<_> = (0..5u64).map(|id| object(id, vec![], vec![id as u8])).collect();
        for elided in 0..5u64 {
            let kept: Vec<_> =
                all.iter().filter(|o| o.object_id.into_inner() != elided).cloned().collect();
            let (_, decoded) = decode_all(&encode_all(&header, &kept));
            let ids: Vec<u64> = decoded.iter().map(|o| o.object_id.into_inner()).collect();
            let expected: Vec<u64> = (0..5u64).filter(|&i| i != elided).collect();
            assert_eq!(ids, expected, "eliding object {elided}");
        }
    }

    // ── Properties blocks ──────────────────────────────

    #[test]
    fn properties_blob_excludes_its_length_prefix() {
        // Vector `subgroup-properties-two-objects-nonempty`: each
        // object carries a two-byte block, so the blob is those two bytes
        // with the `02` length prefix stripped.
        let bytes = hex("1101008000023c0204deadbeef00023c0302cafe");
        let (_, objects) = decode_all(&bytes);
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].object_id.into_inner(), 0);
        assert_eq!(objects[1].object_id.into_inner(), 1);
        assert_eq!(objects[0].extension_headers, hex("3c02"));
        assert_eq!(objects[1].extension_headers, hex("3c03"));
        assert_eq!(objects[0].payload, hex("deadbeef"));
        assert_eq!(objects[1].payload, hex("cafe"));
    }

    #[test]
    fn status_object_carries_its_properties_block() {
        let (_, objects) = decode_all(&hex("1101008000023c010003"));
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].extension_headers, hex("3c01"));
        assert_eq!(objects[0].payload_length.into_inner(), 0);
        assert_eq!(objects[0].object_status.map(ObjectStatus::as_u64), Some(3));
        assert!(objects[0].payload.is_empty());
    }

    // ── Re-encoding ─────────────────────────────────────────

    #[test]
    fn vectors_re_encode_byte_identically() {
        for vector in VECTORS {
            let bytes = hex(vector);
            let (header, objects) = decode_all(&bytes);
            assert_eq!(encode_all(&header, &objects), bytes, "[{vector}] re-encode");
        }
    }

    // ── Payload-free framing ────────────────────────────────

    #[test]
    fn meta_matches_read_object() {
        for vector in VECTORS {
            let bytes = hex(vector);
            let mut cursor = &bytes[..];
            let header = SubgroupHeader::decode(&mut cursor).unwrap();
            let mut full_reader = SubgroupObjectReader::new(&header);
            let mut meta_reader = SubgroupObjectReader::new(&header);
            let mut full_cursor = cursor;
            let mut meta_cursor = cursor;
            while meta_cursor.has_remaining() {
                let before = meta_cursor.remaining();
                let object = full_reader.read_object(&mut full_cursor).unwrap();
                let meta = meta_reader.read_object_meta(&mut meta_cursor).unwrap();
                assert_eq!(meta.object_id, object.object_id.into_inner(), "[{vector}]");
                assert_eq!(
                    meta.extension_headers_len,
                    object.extension_headers.len() as u64,
                    "[{vector}]"
                );
                assert_eq!(meta.payload_length, object.payload_length.into_inner(), "[{vector}]");
                assert_eq!(
                    meta.status,
                    object.object_status.map(ObjectStatus::as_u64),
                    "[{vector}]"
                );
                assert_eq!(meta.wire_len, (before - meta_cursor.remaining()) as u64, "[{vector}]");
                assert_eq!(full_cursor.remaining(), meta_cursor.remaining(), "[{vector}]");
            }
        }
    }

    #[test]
    fn short_buffers_report_unexpected_end() {
        let bytes = hex("1101008000023c0204deadbeef00023c0302cafe");
        let mut cursor = &bytes[..];
        let header = SubgroupHeader::decode(&mut cursor).unwrap();
        let objects_start = bytes.len() - cursor.len();
        for cut in objects_start..bytes.len() {
            let mut reader = SubgroupObjectReader::new(&header);
            let mut meta_reader = SubgroupObjectReader::new(&header);
            let mut cursor = &bytes[objects_start..cut];
            let mut meta_cursor = cursor;
            while cursor.has_remaining() {
                if let Err(err) = reader.read_object(&mut cursor) {
                    assert!(
                        matches!(err, CodecError::UnexpectedEnd | CodecError::VarInt(_)),
                        "cut {cut} gave {err:?}"
                    );
                    break;
                }
            }
            while meta_cursor.has_remaining() {
                if let Err(err) = meta_reader.read_object_meta(&mut meta_cursor) {
                    assert!(
                        matches!(err, CodecError::UnexpectedEnd | CodecError::VarInt(_)),
                        "cut {cut} gave {err:?}"
                    );
                    break;
                }
            }
        }
    }

    // ── Object status ───────────────────────────────────────

    /// A one-object subgroup stream whose object carries `status` in place of
    /// a payload: header type 0x10 (no properties, subgroup-ID mode 0, no
    /// FIRST_OBJECT bit), track alias 1, group 0, publisher priority 128; then
    /// an Object ID delta of 0, a payload length of 0, and the status code.
    fn subgroup_status_stream(status: u64) -> Vec<u8> {
        vec![0x10, 0x01, 0x00, 0x80, 0x00, 0x00, status as u8]
    }

    /// A status datagram carrying `status`: type 0x20 (STATUS bit set,
    /// explicit Object ID, explicit priority), track alias 1, group 0, object
    /// 0, priority 128, then the status byte.
    fn status_datagram(status: u64) -> Vec<u8> {
        vec![0x20, 0x01, 0x00, 0x00, 0x80, status as u8]
    }

    /// The object [`subgroup_status_stream`] describes, as a value.
    fn status_object(status: Option<ObjectStatus>) -> SubgroupObject {
        SubgroupObject {
            object_id: vi(0),
            extension_headers: Vec::new(),
            payload_length: vi(0),
            object_status: status,
            payload: Vec::new(),
        }
    }

    /// The datagram [`status_datagram`] describes, as a value.
    fn status_datagram_header(status: Option<ObjectStatus>) -> DatagramHeader {
        DatagramHeader {
            datagram_type: 0x20,
            track_alias: vi(1),
            group_id: vi(0),
            object_id: vi(0),
            publisher_priority: Some(128),
            properties: Vec::new(),
            object_status: status,
        }
    }

    /// Every status draft-18 assigns can be written and read back as the same
    /// status, on both a subgroup stream and a status datagram.
    ///
    /// The set is read from `ObjectStatus::ALL` rather than restated here, so
    /// this moves with the draft if a code is ever reassigned. It is the gate
    /// on typing the two `object_status` fields: a typed field that silently
    /// narrowed or renumbered the set would fail here even though it still
    /// compiled.
    ///
    /// Writing `ObjectStatus::Normal` when a zero-length object's status is
    /// `None` is checked too — without it the encoder emits an object whose
    /// declared payload length promises a status field that never arrives.
    ///
    /// Made `write_object` encode a constant `ObjectStatus::Normal` instead of
    /// the object's own status, ran it, and got:
    ///
    /// ```text
    /// assertion `left == right` failed: subgroup object status
    ///   left: Some(Normal)
    ///  right: Some(EndOfGroup)
    /// ```
    ///
    /// The same change to `DatagramHeader::encode` gives:
    ///
    /// ```text
    /// assertion `left == right` failed: datagram object status
    ///   left: Some(Normal)
    ///  right: Some(EndOfGroup)
    /// ```
    #[test]
    fn every_assigned_status_survives_a_round_trip() {
        let header = SubgroupHeader::decode(&mut &hex("100100800004deadbeef")[..]).unwrap();
        for &status in ObjectStatus::ALL {
            let mut buf = Vec::new();
            SubgroupObjectReader::new(&header)
                .write_object(&status_object(Some(status)), &mut buf)
                .unwrap_or_else(|e| panic!("write_object refused {status:?}: {e:?}"));

            let mut cursor = &buf[..];
            let object =
                SubgroupObjectReader::new(&header).read_object(&mut cursor).unwrap_or_else(|e| {
                    panic!("read_object refused the bytes written for {status:?}: {e:?}")
                });
            assert_eq!(object.object_status, Some(status), "subgroup object status");
            assert!(!cursor.has_remaining(), "{status:?}: bytes left over after read_object");

            let meta =
                SubgroupObjectReader::new(&header).read_object_meta(&mut &buf[..]).unwrap_or_else(
                    |e| panic!("read_object_meta refused the bytes written for {status:?}: {e:?}"),
                );
            assert_eq!(meta.status, Some(status.as_u64()), "subgroup meta status");

            let mut datagram = Vec::new();
            status_datagram_header(Some(status)).encode(&mut datagram);
            let decoded = DatagramHeader::decode(&mut &datagram[..]).unwrap_or_else(|e| {
                panic!("datagram decode refused the bytes written for {status:?}: {e:?}")
            });
            assert_eq!(decoded.object_status, Some(status), "datagram object status");
        }

        let mut buf = Vec::new();
        SubgroupObjectReader::new(&header).write_object(&status_object(None), &mut buf).unwrap();
        let object = SubgroupObjectReader::new(&header)
            .read_object(&mut &buf[..])
            .expect("a zero-length object with no status must still decode");
        assert_eq!(object.object_status, Some(ObjectStatus::Normal));

        let mut datagram = Vec::new();
        status_datagram_header(None).encode(&mut datagram);
        let decoded = DatagramHeader::decode(&mut &datagram[..])
            .expect("a status datagram with no status must still decode");
        assert_eq!(decoded.object_status, Some(ObjectStatus::Normal));
    }

    /// The encoder writes exactly the frames the decoder accepts.
    ///
    /// Sweeps every status code `0x00..=0x3f` — one wire byte under both the
    /// varint on a subgroup stream and the bare byte on a datagram, and wide
    /// enough to contain the gap at `0x2` and the `0x1` draft-16 dropped. For
    /// a code the draft assigns, the hand-built frame must decode *and* the
    /// encoder handed that status must reproduce those exact bytes. For a code
    /// it does not assign, the same frame must be refused at all three decode
    /// sites — and no `ObjectStatus` exists to hand the encoder, so the frame
    /// has no way to be produced in the first place.
    ///
    /// # What this catches, observed by making each change and running it
    ///
    /// Encoding a constant `ObjectStatus::Normal` in `write_object` instead of
    /// the object's own status:
    ///
    /// ```text
    /// assertion `left == right` failed: the encoder must produce the frame the decoder accepted for status 0x3
    ///   left: [16, 1, 0, 128, 0, 0, 0]
    ///  right: [16, 1, 0, 128, 0, 0, 3]
    /// ```
    ///
    /// The same change in `DatagramHeader::encode`:
    ///
    /// ```text
    /// assertion `left == right` failed: the encoder must produce the datagram the decoder accepted for status 0x3
    ///   left: [32, 1, 0, 0, 128, 0]
    ///  right: [32, 1, 0, 0, 128, 3]
    /// ```
    ///
    /// The decoder drifting away from `ALL` — adding `0x2` to
    /// `ObjectStatus::from_u64`, so a code the draft does not assign starts
    /// decoding:
    ///
    /// ```text
    /// subgroup read_object accepted status 0x2, which the draft does not assign
    /// ```
    ///
    /// # The encode-side refusal is a type, not an assertion
    ///
    /// Once `object_status` is typed there is no runtime path that offers the
    /// encoder a `0x2`, so no test here can watch one be refused. Reverting
    /// `DatagramHeader::object_status` to `Option<u8>` with an `unwrap_or(0)`
    /// encoder does not make this test fail — it makes it stop compiling,
    /// which is the guarantee:
    ///
    /// ```text
    /// error[E0308]: mismatched types
    ///     = note: expected enum `Option<u8>`
    ///                found enum `Option<draft18::types::ObjectStatus>`
    /// ```
    #[test]
    fn the_encoder_writes_exactly_the_frames_the_decoder_accepts() {
        for code in 0x00u64..=0x3f {
            let assigned = ObjectStatus::ALL.iter().copied().find(|s| s.as_u64() == code);

            let stream = subgroup_status_stream(code);
            let mut cursor: &[u8] = &stream;
            let header = SubgroupHeader::decode(&mut cursor).unwrap();
            let objects = cursor;
            let read = SubgroupObjectReader::new(&header).read_object(&mut { objects });
            let meta = SubgroupObjectReader::new(&header).read_object_meta(&mut { objects });

            let datagram = status_datagram(code);
            let decoded = DatagramHeader::decode(&mut &datagram[..]);

            match assigned {
                Some(status) => {
                    let object = read.unwrap_or_else(|e| {
                        panic!(
                            "read_object refused status {code:#x}, which the draft assigns: {e:?}"
                        )
                    });
                    assert_eq!(object.object_status, Some(status));
                    assert_eq!(meta.unwrap().status, Some(code));
                    assert_eq!(decoded.unwrap().object_status, Some(status));

                    let mut written = Vec::new();
                    header.encode(&mut written);
                    SubgroupObjectReader::new(&header)
                        .write_object(&status_object(Some(status)), &mut written)
                        .unwrap();
                    assert_eq!(
                        written, stream,
                        "the encoder must produce the frame the decoder accepted for status {code:#x}"
                    );

                    let mut written = Vec::new();
                    status_datagram_header(Some(status)).encode(&mut written);
                    assert_eq!(
                        written, datagram,
                        "the encoder must produce the datagram the decoder accepted for status {code:#x}"
                    );
                }
                None => {
                    for (site, result) in [
                        ("subgroup read_object", read.map(|_| ())),
                        ("subgroup read_object_meta", meta.map(|_| ())),
                        ("status datagram", decoded.map(|_| ())),
                    ] {
                        match result {
                            Ok(()) => panic!(
                                "{site} accepted status {code:#x}, which the draft does not assign"
                            ),
                            Err(error) => assert!(
                                matches!(error, CodecError::InvalidField),
                                "{site} refused status {code:#x} with {error:?}, not InvalidField"
                            ),
                        }
                    }
                }
            }
        }
    }

    /// The same datagram as [`status_datagram_header`] but under type 0x00 —
    /// every bit clear, so the STATUS bit is clear and a payload follows the
    /// header instead of a status field.
    fn payload_datagram_header(status: Option<ObjectStatus>) -> DatagramHeader {
        DatagramHeader { datagram_type: 0x00, ..status_datagram_header(status) }
    }

    /// A status the type byte gives no room for is refused, not dropped.
    ///
    /// A datagram carries its status only when its type byte sets the STATUS
    /// bit. A header holding End of Group under a type byte without that bit is
    /// asking for a field the framing does not have, and
    /// [`DatagramHeader::encode`] answers by writing the datagram without it —
    /// the loss this gate exists for. What arrives is an ordinary payload
    /// object with no marker at all, indistinguishable from one that never
    /// carried a status, and the middle of this test observes exactly that, so
    /// the gate states the old behaviour as well as the new.
    ///
    /// The statuses come from `ObjectStatus::ALL` rather than a list written
    /// here, so the sweep follows the draft's set instead of a copy of it.
    /// Normal is exempt and checked separately: draft-18 Section 11.2.1.1 says
    /// "Any object with a status code other than zero MUST have an empty
    /// payload", so Normal is the status a payload-bearing datagram already
    /// has, and naming it asks for the same bytes as leaving it out — which is
    /// the last assertion here.
    ///
    /// # What this catches, observed by making each change and running it
    ///
    /// Dropping the check from `encode_checked`, leaving the type byte to
    /// decide on its own as it did before:
    ///
    /// ```text
    /// encode_checked must refuse EndOfGroup under a type byte with no STATUS bit; got Ok(())
    /// ```
    ///
    /// Testing the status instead of the type byte — refusing every non-Normal
    /// status, which also rejects the status datagrams that exist to carry one:
    ///
    /// ```text
    /// encode_checked refused EndOfGroup on a datagram whose type byte carries a status: InvalidField
    /// ```
    ///
    /// Widening the check to refuse a payload datagram whose status is Normal:
    ///
    /// ```text
    /// encode_checked refused a Normal status under a payload type byte: InvalidField
    /// ```
    #[test]
    fn encode_checked_refuses_a_status_the_type_byte_hides() {
        for &status in ObjectStatus::ALL {
            if status == ObjectStatus::Normal {
                continue;
            }

            let header = payload_datagram_header(Some(status));
            let mut refused = Vec::new();
            let result = header.encode_checked(&mut refused);
            assert!(
                matches!(result, Err(CodecError::InvalidField)),
                "encode_checked must refuse {status:?} under a type byte with no STATUS bit; \
                 got {result:?}"
            );
            assert!(refused.is_empty(), "a refused {status:?} header still wrote {refused:?}");

            // What the refusal replaces: the infallible encode writes the
            // header without the status, and it decodes back with none.
            let mut dropped = Vec::new();
            header.encode(&mut dropped);
            let decoded = DatagramHeader::decode(&mut &dropped[..])
                .unwrap_or_else(|e| panic!("the lossy encoding of {status:?} must parse: {e:?}"));
            assert_eq!(
                decoded.object_status, None,
                "{status:?} under a payload type byte is exactly the status `encode` loses"
            );
            assert!(!decoded.has_status(), "the lossy encoding must not claim a status field");

            // The type byte that does carry a status field takes the same
            // status without complaint — the refusal is about the framing, not
            // about the status.
            let mut carried = Vec::new();
            status_datagram_header(Some(status)).encode_checked(&mut carried).unwrap_or_else(|e| {
                panic!("encode_checked refused {status:?} on a datagram whose type byte carries a status: {e:?}")
            });
            let decoded = DatagramHeader::decode(&mut &carried[..]).unwrap();
            assert_eq!(decoded.object_status, Some(status), "{status:?} lost its status");
        }

        // Normal under a payload type byte asks for the bytes the encoding
        // already writes for a datagram with no status field, so it is
        // accepted and produces exactly those bytes.
        let mut named = Vec::new();
        payload_datagram_header(Some(ObjectStatus::Normal))
            .encode_checked(&mut named)
            .unwrap_or_else(|e| {
                panic!("encode_checked refused a Normal status under a payload type byte: {e:?}")
            });
        let mut unnamed = Vec::new();
        payload_datagram_header(None).encode_checked(&mut unnamed).unwrap();
        assert_eq!(named, unnamed, "naming Normal must ask for the bytes leaving it out asks for");
    }
}

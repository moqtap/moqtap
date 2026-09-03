//! Draft-17 data stream header encoding and decoding.
//!
//! Subgroup header type byte: 0b00X1XXXX (bit 4 always set)
//!   - bit 0 (0x01): PROPERTIES
//!   - bits 1-2 (0x06): SUBGROUP_ID_MODE (0=zero, 1=first_obj, 2=explicit, 3=reserved)
//!   - bit 3 (0x08): END_OF_GROUP
//!   - bit 5 (0x20): DEFAULT_PRIORITY (no priority byte)
//!
//! Datagram type byte: 0b00X0XXXX (bit 4 always 0)
//!   - bit 0 (0x01): PROPERTIES
//!   - bit 1 (0x02): END_OF_GROUP
//!   - bit 2 (0x04): ZERO_OBJECT_ID (object_id=0, field omitted)
//!   - bit 3 (0x08): DEFAULT_PRIORITY (no priority byte)
//!   - bit 5 (0x20): STATUS (status byte replaces payload)
//!
//! Neither range is fully populated. Draft-17 Sections 10.4.2 and 10.3.1 each
//! close with a list of type values an endpoint "MUST close the session with a
//! PROTOCOL_VIOLATION" on receiving, and the two figures spell the surviving
//! values out: `0x10..0x15 / 0x18..0x1D / 0x30..0x35 / 0x38..0x3D` for a
//! subgroup header, `0x00..0x0F / 0x20..0x21 / 0x24..0x25 / 0x28..0x29 /
//! 0x2C..0x2D` for a datagram. Both decoders refuse everything else, so a
//! header this module hands back always describes a framing the draft defines.
//!
//! Fetch header: stream type 0x05 + request_id, followed by objects whose
//! fields are named by a Serialization Flags varint rather than all being
//! present — see [`FetchObjectHeader`].

use bytes::{Buf, BufMut};

use super::types::ObjectStatus;
use crate::error::CodecError;
use crate::varint::{Moqt17 as Wire, VarInt};

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
/// draft-17 does not assign.
///
/// Draft-17 Section 10.2.1.1 lists the codes an object may carry and says any
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

/// Whether an object carrying a given status is allowed a non-empty payload.
///
/// Draft-17 Section 10.2.1.1 states the rule arithmetically rather than as a
/// table: "Any object with a status code other than zero MUST have an empty
/// payload." So the answer is a property of the status code, and every code but
/// Normal forbids a payload.
///
/// Forbidding is the strict half; permitting is not requiring. A Normal object
/// with no payload is well formed, and this draft's encodings have a way to
/// spell it — a zero Object Payload Length followed by the status code 0x0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadPermission {
    /// The status permits a payload but does not require one.
    Permitted,
    /// An object with this status has an empty payload, and one carrying bytes
    /// is malformed.
    Forbidden,
}

impl PayloadPermission {
    /// `true` for [`PayloadPermission::Permitted`].
    ///
    /// The permission answers on its own, without a payload length in hand,
    /// which is the point of reading it off the status.
    pub fn permits(self) -> bool {
        matches!(self, PayloadPermission::Permitted)
    }
}

// ── Subgroup ──────────────────────────────────────────────────

const SUBGROUP_PROPERTIES_BIT: u8 = 0x01;
const SUBGROUP_ID_MODE_MASK: u8 = 0x06;
const SUBGROUP_END_OF_GROUP_BIT: u8 = 0x08;
const SUBGROUP_BASE_BIT: u8 = 0x10;
const SUBGROUP_DEFAULT_PRIORITY_BIT: u8 = 0x20;
/// The bits a subgroup header type must fix: 7 and 6 clear, 4 set. That is the
/// form `0b00X1XXXX` written as a mask, leaving bit 5 and the low nibble free.
const SUBGROUP_FORM_MASK: u8 = 0xD0;
/// SUBGROUP_ID_MODE `0b11`, the value draft-17 reserves.
const SUBGROUP_ID_MODE_RESERVED: u8 = 0x06;

/// Whether `header_type` is one of the subgroup header types draft-17 defines.
///
/// Section 10.4.2 gives the field as
/// `Type (i) = 0x10..0x15 / 0x18..0x1D / 0x30..0x35 / 0x38..0x3D` and then
/// names the two ways a byte falls outside it, each of which "MUST close the
/// session with a PROTOCOL_VIOLATION":
///
/// - "Type values with SUBGROUP_ID_MODE set to 0b11: 0x16, 0x17, 0x1E, 0x1F,
///   0x36, 0x37, 0x3E, 0x3F. This mode is reserved for future use."
/// - "Type values that do not match the form 0b00X1XXXX (i.e., Type values
///   outside the ranges 0x10..0x1F and 0x30..0x3F, or values where bit 4 is not
///   set)."
///
/// The two conditions are checked here rather than the eight-value list, and
/// they enumerate exactly the same bytes: the form fixes bits 7, 6 and 4, and
/// excluding the reserved mode removes eight of the remaining thirty-two.
///
/// The reserved mode is the one worth naming. Its Subgroup ID field is not on
/// the wire and the draft does not say what the ID would be, so accepting it
/// means answering with a value nothing in the header stands behind — a zero a
/// consumer cannot tell from the zero mode `0b00` genuinely means.
fn subgroup_type_is_valid(raw: u64) -> bool {
    raw <= 0xFF && {
        let t = raw as u8;
        t & SUBGROUP_FORM_MASK == SUBGROUP_BASE_BIT
            && t & SUBGROUP_ID_MODE_MASK != SUBGROUP_ID_MODE_RESERVED
    }
}

/// Whether `raw` sits inside the subgroup form but names the reserved
/// SUBGROUP_ID_MODE — the first of the two lists quoted above.
fn subgroup_type_is_reserved_mode(raw: u64) -> bool {
    raw <= 0xFF && {
        let t = raw as u8;
        t & SUBGROUP_FORM_MASK == SUBGROUP_BASE_BIT
            && t & SUBGROUP_ID_MODE_MASK == SUBGROUP_ID_MODE_RESERVED
    }
}

/// The unidirectional stream Type draft-17 Section 9.4 gives the control
/// stream.
///
/// Draft-17 is where the control stream became a pair of unidirectional streams
/// with a type of their own, which is why Table 3 has an entry a data reader can
/// be handed and drafts 16 and below do not.
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
/// an assigned Type that is not a data stream — SETUP, a Type no table
/// assigns, or a non-minimal spelling of a Type that is valid. The last is the
/// dangerous one — narrowing a two-byte 0x8001 to its low octet turns it into
/// an assigned Type, so a peer could name any Type it liked and have it parsed
/// as another.
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
/// Draft-17 states two rules about such a Type and answers both with a close,
/// and telling them apart is the whole job of this function.
///
/// Section 3.4 is about the table: "An endpoint that receives an unknown stream
/// type MUST close the session." A Type Table 3 does not assign is
/// [`CodecError::UnknownStreamType`].
///
/// Section 10.4.2 is about the subgroup form specifically, and the eight Types
/// inside it that name the reserved SUBGROUP_ID_MODE. Those are not unknown —
/// the form is assigned and the draft lists the values outright — but they are
/// unreadable, and they are [`CodecError::InvalidTypeValue`].
///
/// Table 3 assigns three things, and two of them are not data streams at all:
/// FETCH_HEADER, the subgroup form, and SETUP. A subgroup reader handed any of
/// them refuses it as [`CodecError::InvalidField`] — the value is one this
/// draft defines, the disagreement is with the reader that was called, and the
/// session survives it. Reporting SETUP as an unknown stream type would end a
/// session over the peer's control stream.
fn stream_type_error(raw: u64) -> CodecError {
    if raw == FETCH_STREAM_TYPE || raw == SETUP_STREAM_TYPE || subgroup_type_is_valid(raw) {
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
    /// Decode a subgroup header, Type field included.
    ///
    /// A Type spelled in more than one byte is refused before it is narrowed,
    /// by `wide_type_refusal`: every Type the subgroup form admits is a
    /// single byte, and the wider Types Table 3 assigns are not subgroup
    /// headers.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        if let Some(err) = wide_type_refusal(buf, stream_type_error)? {
            return Err(err);
        }
        let raw = buf.get_u8() as u64;
        if !subgroup_type_is_valid(raw) {
            return Err(stream_type_error(raw));
        }
        let header_type = raw as u8;

        let track_alias = VarInt::decode_moqt::<Wire>(buf)?;
        let group_id = VarInt::decode_moqt::<Wire>(buf)?;

        let subgroup_id_mode = (header_type & SUBGROUP_ID_MODE_MASK) >> 1;
        let subgroup_id = match subgroup_id_mode {
            0 => VarInt::from_u64_moqt(0),
            2 => VarInt::decode_moqt::<Wire>(buf)?,
            // Mode 1: the Subgroup ID is the first object's Object ID, which is
            // not in the header. Stored as 0 and resolved by whoever reads the
            // first object; [`Self::subgroup_id_mode`] is what tells a caller
            // the stored value is a placeholder. Mode 3 cannot arrive here —
            // `subgroup_type_is_valid` refused it above.
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

    /// Serialize the header exactly as its type byte describes it.
    ///
    /// The type byte is taken as the authority on framing and is written
    /// through unexamined, which is what makes this infallible. A value built
    /// by hand can therefore name a type draft-17 forbids — the reserved
    /// SUBGROUP_ID_MODE `0b11` above all — and produce a stream the receiver
    /// must answer with a PROTOCOL_VIOLATION. Prefer [`Self::encode_checked`],
    /// which refuses such a header instead of emitting it.
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

    /// Serialize the header, refusing a type value draft-17 does not define.
    ///
    /// The accepted set is the one [`Self::decode`] accepts, so bytes this
    /// writes always parse back through this module rather than being refused
    /// by the peer. Section 10.4.2 lists the excluded values under "The
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
    ///
    /// A decoded header never reports `3`: draft-17 Section 10.4.2 lists every
    /// type value carrying that mode as invalid and [`Self::decode`] refuses
    /// them. It remains reachable on a header built by hand, which is what
    /// [`Self::encode_checked`] exists to catch.
    pub fn subgroup_id_mode(&self) -> u8 {
        (self.header_type & SUBGROUP_ID_MODE_MASK) >> 1
    }

    pub fn is_end_of_group(&self) -> bool {
        self.header_type & SUBGROUP_END_OF_GROUP_BIT != 0
    }
}

// ── Subgroup objects (stateful) ───────────────────────────────

/// One object within a draft-17 subgroup stream. Object IDs are
/// delta-encoded and the presence of a "properties" block (the
/// draft-17 equivalent of extension headers) is determined by the
/// PROPERTIES bit on the enclosing [`SubgroupHeader`]. Use
/// [`SubgroupObjectReader`] to encode/decode.
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
    /// [`ObjectStatus::Normal`], the status draft-17 Section 10.2.1.1 gives an
    /// empty object.
    ///
    /// Typed rather than a raw code. The wire field is a varint with room for
    /// any value, and draft-17 assigns three of them; the decoder refuses the
    /// rest, and this type is that same refusal on the encode side — 0x1 and
    /// 0x2 cannot be named here, so [`SubgroupObjectReader::write_object`]
    /// cannot emit a status this module's own decoder would reject.
    pub object_status: Option<ObjectStatus>,
    pub payload: Vec<u8>,
}

impl SubgroupObject {
    /// The object's status, with the one draft-17's encoding elides filled in.
    ///
    /// A subgroup object states its status only when its Object Payload Length
    /// is zero. An object that carries bytes therefore has no status field, and
    /// its status is [`ObjectStatus::Normal`] — the only status draft-17
    /// Section 10.2.1.1 permits a payload, so the only one such an object could
    /// have had.
    pub fn status(&self) -> ObjectStatus {
        self.object_status.unwrap_or(ObjectStatus::Normal)
    }

    /// Whether this object's status is allowed to carry the properties it has.
    ///
    /// Draft-17 Section 10.2.1.2: "Any Object with status Normal can have
    /// properties (Section 2.5). If an endpoint receives properties on an Object with status
    /// that is not Normal, it MUST close the session with a
    /// PROTOCOL_VIOLATION."
    ///
    /// So this is `false` for exactly one shape: a non-empty properties block
    /// on an object whose status is not [`ObjectStatus::Normal`]. An object
    /// with no properties is fine at any status, and an object at Normal may
    /// carry any properties. A zero-length block is "no properties" here and
    /// not a violation — Section 10.4.2 requires it of an object on a
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
    /// one: Section 10.3.1 states the same rule again as a per-datagram
    /// framing rule, so [`DatagramHeader::decode`] refuses it outright.
    pub fn properties_permitted(&self) -> bool {
        self.extension_headers.is_empty() || self.status() == ObjectStatus::Normal
    }
}

/// The framing of one draft-17 subgroup object, without its payload.
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
    /// Whether this object's stated status allows it a non-empty payload.
    ///
    /// `None` when the object states no status at all. On a subgroup stream
    /// that is every object that carries bytes: draft-17 Section 10.4.2 puts
    /// the status field on the wire only when the Object Payload Length is
    /// zero, and Section 10.2.1.1 says Normal "is implicit for any non-zero
    /// length object". An absent status is therefore not an unknown one — it is
    /// Normal, spelled by the payload's own presence — but it is not a *stated*
    /// permission, and this method reports only what the object states.
    ///
    /// `Some` otherwise, reading draft-17 Section 10.2.1.1's rule off the code:
    /// "Any object with a status code other than zero MUST have an empty
    /// payload." Zero permits, everything else forbids, which holds for codes
    /// beyond the three the draft assigns as well — the rule is arithmetic, not
    /// a lookup, so it does not go stale if a later draft assigns more.
    ///
    /// Worth having even though a stated status here always sits beside a zero
    /// payload length, because the framing is not the destination. A caller
    /// forwarding this object onto a datagram, where the payload is whatever
    /// follows the header rather than a counted field, needs to know the object
    /// may not be given bytes there either; the length it read on this stream
    /// says nothing about that.
    pub fn payload_permission(&self) -> Option<PayloadPermission> {
        self.status.map(|code| {
            if code == ObjectStatus::Normal.as_u64() {
                PayloadPermission::Permitted
            } else {
                PayloadPermission::Forbidden
            }
        })
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
    /// every value that can reach this method is one draft-17 assigns and one
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
/// The bits a datagram type must fix: 7, 6 and 4 all clear. That is the form
/// `0b00X0XXXX` written as a mask, leaving bit 5 and the low nibble free.
const DATAGRAM_FORM_MASK: u8 = 0xD0;

/// Whether `datagram_type` is one of the datagram types draft-17 defines.
///
/// Section 10.3.1 gives the field as
/// `Type (i) = 0x00..0x0F / 0x20..0x21 / 0x24..0x25 / 0x28..0x29 / 0x2C..0x2D`
/// and then names the two ways a byte falls outside it, each of which "MUST
/// close the session with a PROTOCOL_VIOLATION":
///
/// - "Type values with both the STATUS bit (0x20) and END_OF_GROUP bit (0x02)
///   set: 0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F. An object status
///   message cannot signal end of group."
/// - "Type values that do not match the form 0b00X0XXXX (i.e., Type values
///   outside the ranges 0x00..0x0F and 0x20..0x2F)."
///
/// The two conditions are checked here rather than the eight-value list, and
/// they enumerate exactly the same bytes.
///
/// Bit 4 is what separates a datagram from a subgroup header: the subgroup form
/// requires it set and this one requires it clear, so the same octet can never
/// be read as both.
fn datagram_type_is_valid(raw: u64) -> bool {
    raw <= 0xFF && {
        let t = raw as u8;
        t & DATAGRAM_FORM_MASK == 0
            && t & (DATAGRAM_STATUS_BIT | DATAGRAM_END_OF_GROUP_BIT)
                != (DATAGRAM_STATUS_BIT | DATAGRAM_END_OF_GROUP_BIT)
    }
}

/// Which failure a leading datagram Type that is not one a reader wants is.
///
/// The same two-rule split as `stream_type_error`, read against the datagram
/// table. A Type outside the datagram form is one no table assigns, so it is
/// [`CodecError::UnknownDatagramType`]. A Type inside the form that sets both
/// STATUS and END_OF_GROUP is named by Section 10.3.1 and forbidden there — an
/// object status message cannot also mark the end of a group — so it is
/// [`CodecError::InvalidTypeValue`].
///
/// Nothing reaches the [`CodecError::InvalidField`] arm from a decoder: the
/// stream Types all set bit 4 or exceed a byte, so they fail the form rather
/// than passing it, and draft-17 defines no padding datagram for the datagram
/// table to share.
fn datagram_type_error(raw: u64) -> CodecError {
    if datagram_type_is_valid(raw) {
        CodecError::InvalidField
    } else if raw <= 0xFF
        && raw as u8 & DATAGRAM_FORM_MASK == 0
        && raw as u8 & (DATAGRAM_STATUS_BIT | DATAGRAM_END_OF_GROUP_BIT)
            == (DATAGRAM_STATUS_BIT | DATAGRAM_END_OF_GROUP_BIT)
    {
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
    /// values, and draft-17 Section 10.2.1.1 assigns three of them; the
    /// decoder refuses the other 253, and this type is that same refusal on
    /// the encode side — [`Self::encode`] is infallible precisely because a
    /// status it could not legally write cannot be built.
    pub object_status: Option<ObjectStatus>,
}

impl DatagramHeader {
    /// Decode the header and stop, leaving whatever follows it in `buf`.
    ///
    /// A datagram's payload has no length field — draft-17 Section 10.3.1:
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
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        if let Some(err) = wide_type_refusal(buf, datagram_type_error)? {
            return Err(err);
        }
        let raw = buf.get_u8() as u64;
        if !datagram_type_is_valid(raw) {
            return Err(datagram_type_error(raw));
        }
        let datagram_type = raw as u8;

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

        // Two rules of draft-17 Section 10.3.1 reach the properties block just
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
    /// that boundary is the only thing that delimits the payload — draft-17
    /// Section 10.3.1: "There is no explicit length field for the Object
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
    /// Section 10.2.1.1's "Any object with a status code other than zero MUST
    /// have an empty payload".
    ///
    /// Errors with [`CodecError::PayloadNotPermitted`] when bytes remain and
    /// the header forbids them, naming which of the two rules refused them.
    ///
    /// # The two Properties rules are enforced here too
    ///
    /// Section 10.3.1 states them of a receiving endpoint, and this is the
    /// endpoint's read:
    ///
    /// * "If an endpoint receives a datagram with the PROPERTIES bit set and an
    ///   Properties Length of 0, it MUST close the session with a
    ///   PROTOCOL_VIOLATION." The bit and a zero length are two ways to spell
    ///   *no properties* and a datagram may use only the first, because a
    ///   datagram with none has a Type that says so and the block costs bytes
    ///   the Type already saved. A subgroup stream says the opposite in
    ///   Section 10.4.2 — there the PROPERTIES bit is fixed for the whole stream,
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
    /// Draft-17 Section 10.3.1 puts the framing side plainly — "The STATUS bit
    /// (0x20) indicates whether the datagram contains an Object Status or
    /// Object Payload" — and Section 10.2.1.1 the conformance side: "Any object
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
    /// A type value Section 10.3.1 lists as invalid is refused here too, on the
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
        // The two properties rules of Section 10.3.1. [`Self::decode`] reports
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
    /// always has a non-empty [`Self::properties`], because
    /// [`Self::decode`] refuses a zero-length block; a header built by hand can
    /// hold the two apart, and [`Self::encode_checked`] is what refuses that.
    pub fn has_properties(&self) -> bool {
        self.datagram_type & DATAGRAM_PROPERTIES_BIT != 0
    }

    /// The object's status, with the one the encoding elides filled in.
    ///
    /// A datagram states a status only when its type sets the STATUS bit, and
    /// such a datagram has no payload. One without the bit is all payload, and
    /// the status of an object that carries a payload is
    /// [`ObjectStatus::Normal`] — draft-17 Section 10.2.1.1: "Any object with a
    /// status code other than zero MUST have an empty payload."
    pub fn status(&self) -> ObjectStatus {
        self.object_status.unwrap_or(ObjectStatus::Normal)
    }

    /// Whether this datagram's status is allowed to carry the properties it
    /// has.
    ///
    /// The same rule the subgroup form obeys. Draft-17 Section 10.3.1 builds
    /// the datagram's Properties field out of "the Object Properties structure
    /// defined in Section 10.2.1.2", and that section is where the general rule
    /// sits: "If an endpoint receives properties on an Object with status that
    /// is not Normal, it MUST close the session with a PROTOCOL_VIOLATION."
    /// Section 10.3.1 then states it again for this carrier in terms of the two
    /// bits, which is why [`Self::decode`] refuses the shape rather than merely
    /// reporting it — see [`SubgroupObject::properties_permitted`] for why the
    /// subgroup carrier is the other way round.
    pub fn properties_permitted(&self) -> bool {
        self.properties.is_empty() || self.status() == ObjectStatus::Normal
    }

    /// Whether the properties block is framed the way a datagram may frame it.
    ///
    /// Draft-17 Section 10.3.1: "If an endpoint receives a datagram with the
    /// PROPERTIES bit set and an Properties Length of 0, it MUST close the
    /// session with a PROTOCOL_VIOLATION."
    ///
    /// The bit and a zero length are two ways to spell "no properties", and on
    /// a datagram they are not interchangeable: a datagram with none has a type
    /// byte that says so, and the block costs bytes the type byte already
    /// saved. This rule is the datagram's alone. A subgroup stream says the
    /// opposite in Section 10.4.2 — "Objects with no properties set Properties
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
    /// Two independent rules forbid them, and this reports both:
    ///
    /// - The framing. Draft-17 Section 10.3.1: "The STATUS bit (0x20) indicates
    ///   whether the datagram contains an Object Status or Object Payload. When
    ///   set to 1, the Object Status field is present and there is no Object
    ///   Payload." A datagram that states a status has no payload field at all,
    ///   whichever status it states — so a STATUS datagram carrying the Normal
    ///   code 0x0 has no more room for bytes than one carrying End of Group.
    /// - The status. Section 10.2.1.1: "Any object with a status code other than
    ///   zero MUST have an empty payload." This one reaches a datagram whose
    ///   type byte leaves the STATUS bit clear while the value claims a
    ///   non-Normal status — a disagreement [`Self::encode_checked`] refuses to
    ///   write, and one a decoded header never shows.
    ///
    /// The first is the rule a decoded datagram can actually trip, and reading
    /// the status alone misses it: `Some(ObjectStatus::Normal)` under a type
    /// byte with the STATUS bit set is exactly the case where the payload the
    /// draft says does not exist would otherwise be handed to the application
    /// as the object's content.
    ///
    /// Distinct from [`Self::has_status`], which reports how the datagram is
    /// framed rather than whether a payload may follow. A caller holding the
    /// bytes after the header wants this one; [`Self::decode_object`] applies it
    /// for a caller who would rather the decode simply fail.
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

/// SUBGROUP mode, the two least significant Serialization Flags bits
/// (draft-17 Section 10.4.4.1, Table 7).
const FETCH_SUBGROUP_MODE_MASK: u64 = 0x03;
/// SUBGROUP mode `0x01`: the Subgroup ID is the prior object's. Mode `0x00`,
/// the remaining value, fixes the Subgroup ID at zero and needs no constant —
/// nothing tests for it.
const FETCH_SUBGROUP_MODE_PRIOR: u64 = 0x01;
/// SUBGROUP mode `0x02`: the Subgroup ID is the prior object's plus one.
const FETCH_SUBGROUP_MODE_PRIOR_PLUS_ONE: u64 = 0x02;
/// SUBGROUP mode `0x03`: an explicit Subgroup ID field is present.
const FETCH_SUBGROUP_MODE_EXPLICIT: u64 = 0x03;
/// Object ID field present; clear means the prior object's ID plus one.
const FETCH_OBJECT_ID_BIT: u64 = 0x04;
/// Group ID field present; clear means the prior object's Group ID.
const FETCH_GROUP_ID_BIT: u64 = 0x08;
/// Priority field present; clear means the prior object's priority.
const FETCH_PRIORITY_BIT: u64 = 0x10;
/// Properties field present.
const FETCH_PROPERTIES_BIT: u64 = 0x20;
/// The object was forwarded as a datagram and has no Subgroup ID; the two
/// least significant bits are to be ignored.
const FETCH_DATAGRAM_BIT: u64 = 0x40;
/// The largest Serialization Flags value read as a set of bits. Draft-17
/// Section 10.4.4: "When less than 128, the bits represent flags described
/// below."
const FETCH_FLAGS_BIT_FORM_MAX: u64 = 0x7f;
/// Serialization Flags `0x8C`, End of Non-Existent Range.
const FETCH_END_OF_NON_EXISTENT_RANGE: u64 = 0x8c;
/// Serialization Flags `0x10C`, End of Unknown Range.
const FETCH_END_OF_UNKNOWN_RANGE: u64 = 0x10c;

/// The two Serialization Flags values that mark a range of Objects rather than
/// carrying one, from draft-17 Section 10.4.4 Table 6 and Section 10.4.4.2.
///
/// Both state a Group ID and an Object ID and nothing else, and both mean the
/// same thing about the span from the last serialized Object to that Location
/// inclusive: it will not be serialized. They differ only in what the publisher
/// claims to know about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndOfRange {
    /// `0x8C`. The Objects in the span "do not exist".
    NonExistent,
    /// `0x10C`. The Objects in the span "are unknown".
    Unknown,
}

/// One object on a draft-17 fetch stream, without its payload.
///
/// Draft-17 Section 10.4.4, Figure 27:
///
/// ```text
/// {
///   Serialization Flags (vi64),
///   [Group ID (vi64),]
///   [Subgroup ID (vi64),]
///   [Object ID (vi64),]
///   [Publisher Priority (8),]
///   [Properties (..),]
///   Object Payload Length (vi64),
///   [Object Payload (..),]
/// }
/// ```
///
/// # Why the fields are optional
///
/// Every bracketed field above is one the Serialization Flags may leave off the
/// wire, and leaving it off does not mean the object lacks it — Table 8 gives
/// each absent field a meaning drawn from the object before it on the stream
/// ("Object ID is the prior Object's ID plus one", "Group ID is the prior
/// Object's Group ID", "Priority is the prior Object's Priority"), and Table 7
/// does the same for the Subgroup ID. A single object's bytes therefore do not
/// determine its Location; only the run of objects before it does.
///
/// So this type reports presence rather than inventing a value: `None` means
/// *the wire did not say*, and resolving it is the job of a caller that has
/// been following the stream. [`Self::references_prior_object`] is how such a
/// caller learns whether resolution is even needed, and it is what makes the
/// draft's rule about the first object checkable: "If the first Object in the
/// FETCH response uses a flag that references fields in the prior Object, the
/// Subscriber MUST close the session with a PROTOCOL_VIOLATION."
///
/// # What draft-17 changed
///
/// Through draft-13 a fetch object spelled out Group ID, Subgroup ID, Object ID
/// and Publisher Priority on every object and carried an Object Status beside a
/// zero-length payload. Draft-17 has neither habit: the flags replace the four
/// unconditional fields, and there is no status field at all — Section 10.2.1.1
/// says the Object Status "is only present in objects that are delivered via a
/// SUBSCRIPTION, and is absent in Objects delivered via a FETCH". A zero
/// `payload_length` here is simply an object with no bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObjectHeader {
    /// The Serialization Flags varint, verbatim.
    ///
    /// Kept whole rather than split into the fields below because it says more
    /// than which fields are present: the two low bits pick between four
    /// Subgroup ID meanings that share one absent field, and the values `0x8C`
    /// and `0x10C` are not bit patterns at all. It is also the authority
    /// [`Self::encode`] writes from.
    pub serialization_flags: VarInt,
    /// Group ID, when the flags put it on the wire.
    pub group_id: Option<VarInt>,
    /// Subgroup ID, present only under SUBGROUP mode `0x03`. The other three
    /// modes leave it off the wire with a meaning of their own, which
    /// [`Self::subgroup_id_mode`] reports.
    pub subgroup_id: Option<VarInt>,
    /// Object ID, when the flags put it on the wire.
    pub object_id: Option<VarInt>,
    /// Publisher priority, when the flags put it on the wire.
    pub publisher_priority: Option<u8>,
    /// Raw properties bytes, excluding the byte-length prefix that precedes
    /// them on the wire. Present only when the flags set the PROPERTIES bit
    /// (0x20), and empty otherwise — the bit is what puts the block on the
    /// wire, so contents held here with the bit clear are not written.
    ///
    /// Opaque, exactly as [`DatagramHeader::properties`] is: the prefix and
    /// these bytes are re-emitted verbatim.
    pub properties: Vec<u8>,
    /// Declared byte length of the payload that follows this header.
    pub payload_length: VarInt,
}

impl FetchObjectHeader {
    /// Decode one fetch object's framing, stopping after the Object Payload
    /// Length.
    ///
    /// The payload itself is left in `buf` — `payload_length` says how many
    /// bytes of it there are, and a caller streaming objects usually wants to
    /// forward or skip them rather than copy them.
    ///
    /// Errors with [`CodecError::InvalidField`] on a Serialization Flags value
    /// draft-17 does not define. Section 10.4.4 reads the value as a bit set
    /// only "when less than 128", names `0x8C` and `0x10C` as the two larger
    /// values that mean anything, and then says of the rest: "Any other value is
    /// a PROTOCOL_VIOLATION."
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let serialization_flags = VarInt::decode_moqt::<Wire>(buf)?;
        let flags = serialization_flags.into_inner();
        if !fetch_flags_are_defined(flags) {
            return Err(CodecError::InvalidField);
        }

        // Read in the order Figure 27 lists them. The presence tests are the
        // ones the accessors below use, applied to the flags just read rather
        // than to a half-built value.
        let group_id =
            if fetch_has_group_id(flags) { Some(VarInt::decode_moqt::<Wire>(buf)?) } else { None };
        let subgroup_id = if fetch_has_subgroup_id(flags) {
            Some(VarInt::decode_moqt::<Wire>(buf)?)
        } else {
            None
        };
        let object_id =
            if fetch_has_object_id(flags) { Some(VarInt::decode_moqt::<Wire>(buf)?) } else { None };
        let publisher_priority = if fetch_has_priority(flags) {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        } else {
            None
        };
        let properties = if fetch_has_properties(flags) {
            let props_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
            crate::types::read_bytes(buf, props_len)?
        } else {
            Vec::new()
        };
        let payload_length = VarInt::decode_moqt::<Wire>(buf)?;

        Ok(FetchObjectHeader {
            serialization_flags,
            group_id,
            subgroup_id,
            object_id,
            publisher_priority,
            properties,
            payload_length,
        })
    }

    /// Serialize the framing, stopping after the Object Payload Length.
    ///
    /// The payload is the caller's to append, matching [`Self::decode`] leaving
    /// it in the buffer.
    ///
    /// Fallible, unlike the other encoders here, because the flags and the
    /// fields can disagree in a way no default resolves. [`DatagramHeader`] can
    /// write a priority the type byte demands and the value omits, because
    /// draft-17 has a default priority to write; a Group ID the flags demand and
    /// the value omits has no such stand-in — every candidate is a Location this
    /// object does not have. Writing nothing there instead would slide the next
    /// field into its place and desynchronize the whole stream, which no reader
    /// downstream could detect, let alone repair.
    ///
    /// Errors with [`CodecError::InvalidField`], before any byte is written, on:
    ///
    /// - a Serialization Flags value draft-17 does not define, the set
    ///   [`Self::decode`] refuses;
    /// - a field the flags announce and the value leaves `None`;
    /// - a field the value supplies and the flags do not announce, including
    ///   non-empty `properties` with the PROPERTIES bit clear — silently
    ///   dropping it would emit an object stripped of metadata that the caller
    ///   believes it sent.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let flags = self.serialization_flags.into_inner();
        if !fetch_flags_are_defined(flags) {
            return Err(CodecError::InvalidField);
        }
        if fetch_has_group_id(flags) != self.group_id.is_some()
            || fetch_has_subgroup_id(flags) != self.subgroup_id.is_some()
            || fetch_has_object_id(flags) != self.object_id.is_some()
            || fetch_has_priority(flags) != self.publisher_priority.is_some()
            || (!fetch_has_properties(flags) && !self.properties.is_empty())
        {
            return Err(CodecError::InvalidField);
        }

        self.serialization_flags.encode_moqt::<Wire>(buf);
        if let Some(group_id) = self.group_id {
            group_id.encode_moqt::<Wire>(buf);
        }
        if let Some(subgroup_id) = self.subgroup_id {
            subgroup_id.encode_moqt::<Wire>(buf);
        }
        if let Some(object_id) = self.object_id {
            object_id.encode_moqt::<Wire>(buf);
        }
        if let Some(priority) = self.publisher_priority {
            buf.put_u8(priority);
        }
        if fetch_has_properties(flags) {
            VarInt::from_usize(self.properties.len()).encode_moqt::<Wire>(buf);
            buf.put_slice(&self.properties);
        }
        self.payload_length.encode_moqt::<Wire>(buf);
        Ok(())
    }

    /// The end-of-range marker this object is, if it is one.
    ///
    /// `None` for every flags value below 128, which is every object that
    /// carries content.
    pub fn end_of_range(&self) -> Option<EndOfRange> {
        match self.serialization_flags.into_inner() {
            FETCH_END_OF_NON_EXISTENT_RANGE => Some(EndOfRange::NonExistent),
            FETCH_END_OF_UNKNOWN_RANGE => Some(EndOfRange::Unknown),
            _ => None,
        }
    }

    /// The SUBGROUP mode: `serialization_flags & 0x03`, per draft-17
    /// Section 10.4.4.1 Table 7.
    ///
    /// `0x00` = the Subgroup ID is zero; `0x01` = it is the prior object's;
    /// `0x02` = it is the prior object's plus one; `0x03` = it is present in
    /// [`Self::subgroup_id`].
    ///
    /// Meaningless when [`Self::is_datagram`] holds — Section 10.4.4.1 says of
    /// the DATAGRAM bit that the subscriber "MUST ignore the bits" — and this
    /// reports the raw two bits regardless, so check that first.
    pub fn subgroup_id_mode(&self) -> u64 {
        self.serialization_flags.into_inner() & FETCH_SUBGROUP_MODE_MASK
    }

    /// Whether the DATAGRAM bit (0x40) is set: the object was forwarded with an
    /// Object Forwarding Preference of Datagram and so has no Subgroup ID at
    /// all.
    pub fn is_datagram(&self) -> bool {
        self.serialization_flags.into_inner() & FETCH_DATAGRAM_BIT != 0
    }

    /// Whether the flags set the PROPERTIES bit (0x20), which is what puts
    /// [`Self::properties`] on the wire.
    pub fn has_properties(&self) -> bool {
        fetch_has_properties(self.serialization_flags.into_inner())
    }

    /// Whether resolving this object's fields requires the object before it on
    /// the stream.
    ///
    /// True when any of the Group ID, Object ID or Priority fields is absent —
    /// draft-17 Section 10.4.4.1 Table 8 defines each absent field in terms of
    /// "the prior Object" — or when the SUBGROUP mode names the prior object's
    /// Subgroup ID or that ID plus one. Mode `0x00` is not such a case: it fixes
    /// the Subgroup ID at zero without consulting anything.
    ///
    /// This is the predicate Section 10.4.4 makes load-bearing: "If the first
    /// Object in the FETCH response uses a flag that references fields in the
    /// prior Object, the Subscriber MUST close the session with a
    /// PROTOCOL_VIOLATION." A single object's bytes cannot tell whether it is
    /// the first, so the decoder cannot enforce that; a caller reading the
    /// stream can, and this is what it asks.
    ///
    /// False for both end-of-range markers. Section 10.4.4.2 fixes their fields
    /// outright — "the Group ID and Object ID fields are present. Subgroup ID,
    /// Priority and Properties are not present" — so a marker inherits nothing,
    /// and the section's own phrase "the last serialized Object, if any" allows
    /// one to open a response.
    pub fn references_prior_object(&self) -> bool {
        if self.end_of_range().is_some() {
            return false;
        }
        let flags = self.serialization_flags.into_inner();
        let inherits_subgroup = !self.is_datagram()
            && matches!(
                flags & FETCH_SUBGROUP_MODE_MASK,
                FETCH_SUBGROUP_MODE_PRIOR | FETCH_SUBGROUP_MODE_PRIOR_PLUS_ONE
            );
        !fetch_has_group_id(flags)
            || !fetch_has_object_id(flags)
            || !fetch_has_priority(flags)
            || inherits_subgroup
    }
}

/// Whether draft-17 defines this Serialization Flags value.
///
/// Section 10.4.4: the value is a bit set "when less than 128"; `0x8C` and
/// `0x10C` are the two larger values Table 6 defines; "Any other value is a
/// PROTOCOL_VIOLATION."
fn fetch_flags_are_defined(flags: u64) -> bool {
    flags <= FETCH_FLAGS_BIT_FORM_MAX
        || flags == FETCH_END_OF_NON_EXISTENT_RANGE
        || flags == FETCH_END_OF_UNKNOWN_RANGE
}

fn fetch_has_group_id(flags: u64) -> bool {
    flags & FETCH_GROUP_ID_BIT != 0
}

/// Whether an explicit Subgroup ID field follows the Group ID.
///
/// The DATAGRAM bit wins over the mode bits. Section 10.4.4.1: "When 0x40 is
/// set, it SHOULD set the two least significant bits to zero and the subscriber
/// MUST ignore the bits." A publisher that sets the bit and leaves the mode at
/// `0x03` anyway has written no Subgroup ID field, so reading one would consume
/// the Object ID in its place.
///
/// Both end-of-range values carry mode `0x00`, which is also what
/// Section 10.4.4.2 requires of them, so they need no case of their own here.
fn fetch_has_subgroup_id(flags: u64) -> bool {
    flags & FETCH_DATAGRAM_BIT == 0
        && flags & FETCH_SUBGROUP_MODE_MASK == FETCH_SUBGROUP_MODE_EXPLICIT
}

fn fetch_has_object_id(flags: u64) -> bool {
    flags & FETCH_OBJECT_ID_BIT != 0
}

fn fetch_has_priority(flags: u64) -> bool {
    flags & FETCH_PRIORITY_BIT != 0
}

fn fetch_has_properties(flags: u64) -> bool {
    flags & FETCH_PROPERTIES_BIT != 0
}

/// One frame from a FETCH stream with the fields its Serialization Flags left
/// off the wire filled in from the frames before it.
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
    /// Section 10.4.4.2: "Prior Priority: The Priority from the last actual
    /// Object before the End of Range indicator."
    ///
    /// The fallback for a subscription that never stated a priority is left to
    /// the caller rather than substituted here, so that "no frame has said"
    /// stays distinguishable from "a frame said 128".
    pub publisher_priority: Option<u8>,
}

/// Resolves the elided fields of the frames on one FETCH stream.
///
/// Draft-17 Section 10.4.4.1, Table 8 defines every field a frame omits as the
/// prior Object's — a Group ID repeated, an Object ID stepped by one, a
/// Priority carried over — and Table 7 does the same for the Subgroup ID, so no
/// frame after the first can be understood on its own. This holds what the
/// frames so far established, in the two parts the draft keeps separate:
/// Section 10.4.4.2 says that after an End of Range marker the prior Group ID
/// and Object ID are the marker's, while the prior Subgroup ID and Priority are
/// still "from the last actual Object before the End of Range indicator".
///
/// Nothing here is a delta. The fields that *are* on the wire hold values
/// rather than differences, which is what separates this from draft-18's reader
/// of the same name: draft-18 renamed both ID fields to deltas and gave them
/// arithmetic, which is also why this reader needs no Group Order and
/// draft-18's does.
#[derive(Debug, Clone, Default)]
pub struct FetchObjectReader {
    /// Group ID and Object ID of the last frame, marker or Object.
    prior_location: Option<(u64, u64)>,
    /// Subgroup ID of the last actual Object that had one.
    prior_subgroup_id: Option<u64>,
    /// Publisher Priority of the last actual Object.
    prior_publisher_priority: Option<u8>,
}

impl FetchObjectReader {
    /// A reader positioned before the first frame of a fetch stream, with no
    /// prior Object to inherit from.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next frame's header and resolve its fields.
    ///
    /// Consumes the header only. The Object Payload is
    /// `header.payload_length` bytes and stays in `buf`, so a caller that
    /// forwards payloads never copies them and one that ignores them can skip.
    ///
    /// Errors with [`CodecError::InvalidField`] when a frame names a field of a
    /// prior Object that does not exist — Section 10.4.4.1: "If the first
    /// Object in the FETCH response uses a flag that references fields in the
    /// prior Object, the Subscriber MUST close the session with a
    /// PROTOCOL_VIOLATION" — and when a Subgroup ID or Object ID one past the
    /// prior one would leave the 64-bit range.
    pub fn read_object_header(&mut self, buf: &mut impl Buf) -> Result<FetchObject, CodecError> {
        let header = FetchObjectHeader::decode(buf)?;

        // An End of Range marker states a Location outright and inherits
        // nothing, so it is resolved before any of the prior-Object rules.
        if header.end_of_range().is_some() {
            let group_id = header.group_id.ok_or(CodecError::InvalidField)?.into_inner();
            let object_id = header.object_id.ok_or(CodecError::InvalidField)?.into_inner();
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

        let group_id = match header.group_id {
            Some(v) => v.into_inner(),
            None => self.prior_location.ok_or(CodecError::InvalidField)?.0,
        };
        let object_id = match header.object_id {
            Some(v) => v.into_inner(),
            None => self
                .prior_location
                .ok_or(CodecError::InvalidField)?
                .1
                .checked_add(1)
                .ok_or(CodecError::InvalidField)?,
        };
        let subgroup_id = if header.is_datagram() {
            None
        } else {
            Some(match header.subgroup_id_mode() {
                0x00 => 0,
                0x01 => self.prior_subgroup_id.ok_or(CodecError::InvalidField)?,
                0x02 => self
                    .prior_subgroup_id
                    .ok_or(CodecError::InvalidField)?
                    .checked_add(1)
                    .ok_or(CodecError::InvalidField)?,
                // Mode 0x03, the only value left: the field is on the wire.
                _ => header.subgroup_id.ok_or(CodecError::InvalidField)?.into_inner(),
            })
        };
        let publisher_priority = match header.publisher_priority {
            Some(p) => p,
            None => self.prior_publisher_priority.ok_or(CodecError::InvalidField)?,
        };

        self.prior_location = Some((group_id, object_id));
        // A Datagram-forwarded object has no Subgroup ID to leave behind, so it
        // does not clear the running one: the object after it inherits from the
        // last object that had one.
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
/// same frames. Removing a frame changes what the frames after it are read
/// against, and draft-17 Section 10.4.4.1 lets an Object leave out its Group
/// ID, Object ID, Subgroup ID and Priority and take the prior Object's, so the
/// survivor that follows a removed run cannot keep its original bytes: a field
/// it left off has to appear, and a flag bit with it.
///
/// # Draft-17 states these fields, it does not delta them
///
/// A Group ID or Object ID that is on the wire here is the absolute value, not
/// a difference — the deltas arrive at draft-18. What is stateful is the
/// *omission*: no Group ID means the prior Object's, and no Object ID means the
/// prior Object's plus one. That is enough to make removal a re-encode, and it
/// is why this writer refuses nothing an Object can be: every identity has an
/// encoding here, however the predecessor moved.
///
/// # Why this is not a general encoder
///
/// Every frame it writes came off a stream, so the caller holds the frame's own
/// [`FetchObjectHeader`] alongside the resolved values, and that header is used
/// as the preference: wherever the original shape still says the same thing
/// against the new predecessor it is kept, so a stream with nothing removed is
/// reproduced byte for byte.
#[derive(Debug, Clone, Default)]
pub struct FetchObjectWriter {
    /// Group ID and Object ID of the last frame written, marker or Object.
    prior_location: Option<(u64, u64)>,
    /// Subgroup ID of the last actual Object written that had one.
    prior_subgroup_id: Option<u64>,
    /// Publisher Priority of the last actual Object written.
    prior_publisher_priority: Option<u8>,
}

impl FetchObjectWriter {
    /// A writer positioned before the first Object of a fetch stream, with no
    /// prior Object for anything to be encoded against.
    pub fn new() -> Self {
        Self::default()
    }

    /// The header that encodes `frame` against everything written so far.
    ///
    /// Does not advance the writer — [`Self::write_object_header`] is the call
    /// that does both.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] for an Object with neither a Subgroup ID
    /// nor the Datagram bit, and for one with no Priority: both are frames no
    /// draft-17 stream could carry, and inventing a value would put a different
    /// Object on the wire than the one this was handed.
    pub fn header_for(&self, frame: &FetchObject) -> Result<FetchObjectHeader, CodecError> {
        let original = &frame.header;

        // An End of Range marker states its Location outright and inherits
        // nothing, so its two fields are the same whatever precedes it.
        if original.end_of_range().is_some() {
            return Ok(FetchObjectHeader {
                serialization_flags: original.serialization_flags,
                group_id: Some(VarInt::from_u64(frame.group_id)?),
                subgroup_id: None,
                object_id: Some(VarInt::from_u64(frame.object_id)?),
                publisher_priority: None,
                properties: Vec::new(),
                payload_length: original.payload_length,
            });
        }

        let (group_id, object_id) = self.identity_fields(frame, original)?;
        let (subgroup_mode, subgroup_id) = self.subgroup_field(frame, original)?;
        let publisher_priority = self.priority_field(frame, original)?;

        let flags = original.serialization_flags.into_inner();
        let mut new_flags = subgroup_mode;
        if flags & FETCH_DATAGRAM_BIT != 0 {
            new_flags |= FETCH_DATAGRAM_BIT;
        }
        if group_id.is_some() {
            new_flags |= FETCH_GROUP_ID_BIT;
        }
        if object_id.is_some() {
            new_flags |= FETCH_OBJECT_ID_BIT;
        }
        if publisher_priority.is_some() {
            new_flags |= FETCH_PRIORITY_BIT;
        }
        if flags & FETCH_PROPERTIES_BIT != 0 {
            new_flags |= FETCH_PROPERTIES_BIT;
        }

        Ok(FetchObjectHeader {
            serialization_flags: VarInt::from_u64(new_flags)?,
            group_id,
            subgroup_id,
            object_id,
            publisher_priority,
            properties: original.properties.clone(),
            payload_length: original.payload_length,
        })
    }

    /// The Group ID and Object ID fields, present only where leaving them off
    /// would say something else.
    ///
    /// Both are absolute when written, so the choice is only whether to write
    /// them, and it is made in favour of the shape the frame arrived in: an
    /// Object that stated its Group ID keeps stating it even where the
    /// predecessor now shares it, which costs the same bytes it already cost.
    fn identity_fields(
        &self,
        frame: &FetchObject,
        original: &FetchObjectHeader,
    ) -> Result<(Option<VarInt>, Option<VarInt>), CodecError> {
        let group_id = match self.prior_location {
            Some((prior_group, _))
                if original.group_id.is_none() && prior_group == frame.group_id =>
            {
                None
            }
            _ => Some(VarInt::from_u64(frame.group_id)?),
        };
        let object_id = match self.prior_location {
            Some((_, prior_object))
                if original.object_id.is_none()
                    && prior_object.checked_add(1) == Some(frame.object_id) =>
            {
                None
            }
            _ => Some(VarInt::from_u64(frame.object_id)?),
        };
        Ok((group_id, object_id))
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
        if original.is_datagram() {
            return Ok((
                original.serialization_flags.into_inner() & FETCH_SUBGROUP_MODE_MASK,
                None,
            ));
        }

        let subgroup_id = frame.subgroup_id.ok_or(CodecError::InvalidField)?;
        let inherits = self.prior_subgroup_id == Some(subgroup_id);
        let successor =
            self.prior_subgroup_id.is_some_and(|p| p.checked_add(1) == Some(subgroup_id));

        // Mode 0x00 is *the Subgroup ID is zero*; the reader reads it that way
        // and there is no named constant for it beside the other three.
        let kept = match original.subgroup_id_mode() {
            0x00 if subgroup_id == 0 => Some((0x00, None)),
            FETCH_SUBGROUP_MODE_PRIOR if inherits => Some((FETCH_SUBGROUP_MODE_PRIOR, None)),
            FETCH_SUBGROUP_MODE_PRIOR_PLUS_ONE if successor => {
                Some((FETCH_SUBGROUP_MODE_PRIOR_PLUS_ONE, None))
            }
            FETCH_SUBGROUP_MODE_EXPLICIT => Some((FETCH_SUBGROUP_MODE_EXPLICIT, Some(subgroup_id))),
            _ => None,
        };
        let (mode, explicit) = match kept {
            Some(pair) => pair,
            None if subgroup_id == 0 => (0x00, None),
            None if inherits => (FETCH_SUBGROUP_MODE_PRIOR, None),
            None if successor => (FETCH_SUBGROUP_MODE_PRIOR_PLUS_ONE, None),
            None => (FETCH_SUBGROUP_MODE_EXPLICIT, Some(subgroup_id)),
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
    /// [`CodecError::InvalidField`] for a frame with no encoding at all; the
    /// writer is left untouched when this happens.
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
    /// `test-vectors/transport/draft17/codec/data-streams/subgroup.json`.
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
    /// a payload: header type 0x10 (no properties, subgroup-ID mode 0), track
    /// alias 1, group 0, publisher priority 128; then an Object ID delta of 0,
    /// a payload length of 0, and the status code.
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

    /// Every status draft-17 assigns can be written and read back as the same
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
    ///                found enum `Option<draft17::types::ObjectStatus>`
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
}

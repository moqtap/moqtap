//! Draft-21 data stream header encoding and decoding.
//!
//! Byte-for-byte identical to draft-19. The field list, the field order, the
//! widths and the set of valid Type values are all unchanged; what draft-20
//! changed is the receive path.
//!
//! # `Type` became `Type Flags`, and the rules left the figure
//!
//! Draft-19 enumerated the legal leading values inside the figure —
//! `Type (vi64) = 0x10..0x15 / 0x18..0x1D / …` for a subgroup header — and
//! draft-21 declares the field a set of flags and states the invalid
//! combinations as prose after it. Computing draft-21's rules gives back
//! draft-19's enumeration byte for byte, on both carriers, so no valid frame
//! changed hands. A decoder that validated by range membership was already
//! right; one that validated loosely, by masking off bits it did not know,
//! becomes wrong.
//!
//! **The two carriers do not share a rule set, and neither can be derived from
//! the other.** Section 11.3.1 gives SUBGROUP_HEADER three conditions and
//! Section 11.2.1 gives OBJECT_DATAGRAM three of its own, and they disagree at
//! two points:
//!
//! * bit 4 (`0x10`) **MUST be 1** on a subgroup header and **MUST be 0** on a
//!   datagram, where it is reserved — the same bit, opposite requirements, and
//!   it is what tells the two carriers apart in the stream-type registry;
//! * the datagram has an "a bit set whose meaning is not specified" condition
//!   and the subgroup header has none, because bits 0 through 6 are all
//!   specified for a subgroup. The subgroup gets an explicit "values of 128 or
//!   greater" condition instead, which the datagram does not have — there the
//!   unspecified-bit rule catches the same values, since 128 sets bit 7.
//!
//! # Non-minimal Type Flags are accepted on receive and never emitted
//!
//! Section 8.1 permits a value to be encoded in more bytes than it needs, and
//! Section 11.3.1 words its third condition as "values of 128 or greater (i.e.,
//! any value that requires more than a one-byte variable-length integer
//! encoding)". Those two clauses are not equivalent under that allowance: the
//! value `0x14` written as the two-byte `0x8014` is a legal varint whose value
//! is below 128 and whose encoding is two bytes. **This codec reads the rule as
//! a bound on the value**, so it decodes such a header, and it always emits the
//! minimal one-byte form. The draft does not settle which clause governs;
//! rejecting a legal-but-non-minimal encoding risks failing a conformant peer
//! and emitting one risks tripping a stricter peer, so the asymmetry is the
//! safe default. Draft-19's decoder refused every wide spelling outright, which
//! is the behaviour this replaces.
//!
//! # The payload rule
//!
//! Unchanged from draft-19, and worth restating because it is the one place
//! where the encoder refuses an object draft-18 would have reinterpreted.
//! Draft-18 said every Object with a status other than Normal has an empty
//! payload; draft-21 Section 11.1.2 says instead that an Object has an empty
//! payload unless its status is registered as permitting one, and
//! Section 16.9 puts that permission in the Object Status registry. Both
//! encodings here keep their draft-18 framing — a subgroup object carries a
//! status exactly when its Object Payload Length is zero, and a datagram
//! carries one exactly when its type sets the STATUS bit, both stated that way
//! by the draft — so no frame these decoders can read is able to state a
//! status and a payload at once. The registry rule therefore bites where a
//! caller can hold both: `SubgroupObjectReader::write_object` consults the
//! status's payload permission and refuses an object whose status forbids the
//! payload handed with it, rather than dropping the status and writing the
//! bytes as a Normal object. On the way back out, `SubgroupObject` and
//! `DatagramHeader` answer the same question from the registry, so a reader
//! never has to recover it from a length.
//!
//! Subgroup Type Flags: form 0b0XX1XXXX, so bit 4 is set and bit 7 is
//! clear; the ranges are 0x10..0x1F, 0x30..0x3F, 0x50..0x5F, 0x70..0x7F.
//!   - bit 0 (0x01): PROPERTIES
//!   - bits 1-2 (0x06): SUBGROUP_ID_MODE (0=zero, 1=first_obj, 2=explicit, 3=reserved)
//!   - bit 3 (0x08): END_OF_GROUP
//!   - bit 5 (0x20): DEFAULT_PRIORITY (no priority byte)
//!   - bit 6 (0x40): FIRST_OBJECT
//!
//! Datagram Type Flags: 0b00X0XXXX, so bits 4, 6 and 7 are clear; the ranges
//! are 0x00..0x0F and 0x20..0x2F.
//!   - bit 0 (0x01): PROPERTIES
//!   - bit 1 (0x02): END_OF_GROUP
//!   - bit 2 (0x04): ZERO_OBJECT_ID (object_id=0, field omitted)
//!   - bit 3 (0x08): DEFAULT_PRIORITY (no priority byte)
//!   - bit 5 (0x20): STATUS (status byte replaces payload)
//!
//! Neither range is fully assigned, and draft-21 spells out which values in
//! them an endpoint must refuse rather than decode, closing the session with a
//! PROTOCOL_VIOLATION. Section 11.3.1 excludes the subgroup Types whose
//! SUBGROUP_ID_MODE is the reserved 0b11 — 0x16, 0x17, 0x1E, 0x1F and the same
//! four offsets in each higher range — because that mode does not say whether
//! a Subgroup ID field follows the Group ID, so a decoder would have to guess
//! and a wrong guess shifts every later field by the width of that varint.
//! Section 11.2.1 excludes the datagram Types setting both STATUS (0x20) and
//! END_OF_GROUP (0x02) — 0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E and 0x2F —
//! because an object status message cannot signal end of group.
//! [`SubgroupHeader::decode`] and [`DatagramHeader::decode`] refuse both
//! lists, and [`SubgroupHeader::encode_checked`] and
//! [`DatagramHeader::encode_checked`] refuse to write them.
//!
//! Fetch header: stream type 0x05 + request_id, then per-object records whose
//! leading Serialization Flags varint says which of the object's fields are on
//! the wire at all; [`FetchObjectHeader`] decodes and encodes one such record.
//! Draft-20 adds a third End of Range marker to Table 7,
//! [`FetchEndOfRange::TimedOut`] (`0x20C`), for the Objects a relay abandoned
//! when its `FILL_TIMEOUT` budget ran out — what draft-19 reported as an
//! Unknown range.

use bytes::{Buf, BufMut};

use super::types::{ObjectStatus, PayloadPermission};
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
/// draft-21 does not assign.
///
/// Draft-21 Section 11.1.2 lists the codes an object may carry — the three
/// rows of the Object Status registry it establishes in Section 16.9 — and
/// says any other value SHOULD be treated as a protocol error and the session
/// closed with a PROTOCOL_VIOLATION. Every place this module reads a status
/// converts it here, so a decoded [`SubgroupObject::object_status`] or
/// [`DatagramHeader::object_status`] is always a status the draft assigns, and
/// [`SubgroupObjectMeta::status`] — which stays a raw code because a relay may
/// carry it to a draft that numbers the set differently — holds one because it
/// comes from the same conversion.
fn decoded_status(code: u64) -> Result<ObjectStatus, CodecError> {
    ObjectStatus::from_u64(code).ok_or(CodecError::InvalidField)
}

// ── Stream and datagram types ─────────────────────────────────

/// Unidirectional stream type for padding, draft-21 Section 11.5.1: "An
/// endpoint MAY open a unidirectional stream with a stream type of 0x132B3E28
/// to send padding data. The stream begins with the stream type, followed by
/// zero or more bytes that MUST all be set to zero."
///
/// Named here because the value is what tells a padding stream from a data
/// stream, and nothing else in this module would otherwise say so. Under the
/// draft-21 variable-length integer encoding the value takes five bytes, the
/// first of which is 0xF0 — an octet with bit 7 set, which the subgroup form
/// leaves clear. A reader judging the Type by that first byte alone would find
/// the form broken and call the stream unknown, which Section 6.4.1 answers by
/// ending the session. Table 2 assigns the value, so that would be a close over
/// traffic this draft permits.
pub const PADDING_STREAM_TYPE: u64 = 0x132B_3E28;

/// Datagram type for padding, draft-21 Section 11.5.2: "An endpoint MAY send a
/// datagram with a type of 0x132B3E29 to send padding data. The datagram
/// contains the type followed by zero or more bytes that MUST all be set to
/// zero."
///
/// One more than [`PADDING_STREAM_TYPE`] and encoded the same width, and
/// assigned the same way, so the same reasoning applies to a datagram reader.
pub const PADDING_DATAGRAM_TYPE: u64 = 0x132B_3E29;

/// The unidirectional stream Type draft-21 Section 9.1 gives the control
/// stream.
const SETUP_STREAM_TYPE: u64 = 0x2F00;

// ── Subgroup ──────────────────────────────────────────────────

const SUBGROUP_PROPERTIES_BIT: u8 = 0x01;
const SUBGROUP_ID_MODE_MASK: u8 = 0x06;
const SUBGROUP_END_OF_GROUP_BIT: u8 = 0x08;
const SUBGROUP_BASE_BIT: u8 = 0x10;
const SUBGROUP_DEFAULT_PRIORITY_BIT: u8 = 0x20;
const SUBGROUP_FIRST_OBJECT_BIT: u8 = 0x40;
/// The SUBGROUP_ID_MODE value draft-21 reserves, once the mask is applied and
/// the field shifted down.
const SUBGROUP_ID_MODE_RESERVED: u8 = 0b11;

/// Refuse a subgroup header `Type Flags` value draft-21 Section 11.3.1 lists
/// as invalid.
///
/// The section gives **three** conditions and says of all of them that an
/// endpoint receiving a stream header with such a value MUST close the session
/// with a PROTOCOL_VIOLATION:
///
///   1. "Values with SUBGROUP_ID_MODE set to 0b11. This mode is reserved for
///      future use." That is 0x16, 0x17, 0x1E, 0x1F and the same four offsets
///      in each higher range.
///   2. "Values where bit 4 is not set. Bit 4 MUST be 1 for SUBGROUP_HEADER."
///   3. "Values of 128 or greater (i.e., any value that requires more than a
///      one-byte variable-length integer encoding)."
///
/// Computing the three gives 0x10-0x15, 0x18-0x1D, 0x30-0x35, 0x38-0x3D,
/// 0x50-0x55, 0x58-0x5D, 0x70-0x75 and 0x78-0x7D — byte for byte the
/// enumeration draft-19 wrote into its figure.
///
/// **These are not the datagram's rules.** Section 11.2.1 reserves bit 4 and
/// requires it to be *zero*, and adds an unspecified-bit condition that this
/// list does not have, because bits 0 through 6 are all specified here. The two
/// sets are read from their own sections and neither is derived from the other.
///
/// The reserved mode is worth separating from a mere unassigned code point,
/// because it is not decodable rather than merely unknown. The other three
/// modes each say whether a Subgroup ID field follows the Group ID; 0b11 says
/// nothing, so a decoder has to guess, and a wrong guess shifts every
/// subsequent field by the width of that varint.
fn validate_subgroup_type(raw: u64) -> Result<(), CodecError> {
    if subgroup_type_is_valid(raw) {
        Ok(())
    } else {
        Err(stream_type_error(raw))
    }
}

/// Whether `raw` is a subgroup `Type Flags` value draft-21 admits: below 128,
/// bit 4 set, and not the reserved SUBGROUP_ID_MODE.
fn subgroup_type_is_valid(raw: u64) -> bool {
    // `raw < 0x80` is Section 11.3.1's third condition, and it subsumes the
    // form's bit-7-clear requirement.
    raw < 0x80 && {
        let t = raw as u8;
        t & SUBGROUP_BASE_BIT != 0 && (t & SUBGROUP_ID_MODE_MASK) >> 1 != SUBGROUP_ID_MODE_RESERVED
    }
}

/// Which failure a leading unidirectional stream Type that is not the one a
/// reader wants is.
///
/// Draft-21 states two rules about such a Type and answers both with a close,
/// and telling them apart is the whole job of this function.
///
/// Section 6.4.1 is about the table: "An endpoint that receives an unknown stream
/// type MUST close the session." A Type Table 2 does not assign is
/// [`CodecError::UnknownStreamType`].
///
/// Section 11.3.1 is about the subgroup form specifically, and gives three
/// conditions on a `Type Flags` value *inside* it. Those values are not unknown
/// — the registry pattern 0b0XX1XXXX assigns the space and the draft rules
/// particular values out within it — but they are unreadable, and they are
/// [`CodecError::InvalidStreamTypeValue`], one arm per condition so a log names which.
///
/// Table 2 assigns four things, and two of them carry no Objects at all:
/// FETCH_HEADER, the subgroup form, SETUP and PADDING. A subgroup reader handed
/// any of them refuses it as [`CodecError::InvalidField`] — the value is one
/// this draft defines, the disagreement is with the reader that was called, and
/// the session survives it. See [`PADDING_STREAM_TYPE`] for why that case in
/// particular is worth the trouble.
///
/// # Where the boundary between the two rules sits
///
/// Section 11.3.1's conditions are about a one-byte flags field, so they are
/// applied to values that fit one — `raw <= 0xFF`. Above that the value is out
/// of the space the section describes and the question is Table 2's instead:
/// an assigned non-subgroup stream type is refused as the wrong reader, and
/// anything else is unknown. That split is what keeps a datagram's
/// `Type Flags` of 0x20 reported as an invalid subgroup value — which is what
/// Section 11.3.1's bit-4 condition calls it — while a stray 0x5000 stays an
/// unknown stream type.
fn stream_type_error(raw: u64) -> CodecError {
    if raw == FETCH_STREAM_TYPE
        || raw == SETUP_STREAM_TYPE
        || raw == PADDING_STREAM_TYPE
        || subgroup_type_is_valid(raw)
    {
        return CodecError::InvalidField;
    }
    if raw > 0xFF {
        return CodecError::UnknownStreamType(raw);
    }
    let t = raw as u8;
    // Third condition first: it is the coarsest, and 128 or more can also set
    // the other two bits in ways that would misreport it.
    if raw >= 0x80 {
        CodecError::InvalidStreamTypeValue {
            raw,
            detail: "SUBGROUP_HEADER Type Flags of 128 or greater are invalid",
        }
    } else if t & SUBGROUP_BASE_BIT == 0 {
        CodecError::InvalidStreamTypeValue { raw, detail: "bit 4 must be 1 for SUBGROUP_HEADER" }
    } else {
        CodecError::InvalidStreamTypeValue {
            raw,
            detail: "its SUBGROUP_ID_MODE is 0b11, which this draft reserves",
        }
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
    /// Decode a subgroup header, `Type Flags` field included.
    ///
    /// The field is read as a whole varint of whatever width the sender used,
    /// and the value it decodes to is what the three Section 11.3.1 conditions
    /// are applied to. **A non-minimal spelling of a valid value is
    /// accepted**: `0x8010` decodes to 16, which is a legal `Type Flags`, and
    /// this reads it. See the module documentation for why the draft leaves
    /// that open and why permissive-on-receive is the choice here; the encoder
    /// is the strict half and always writes the one-byte form.
    ///
    /// Draft-19 refused every wide spelling before looking at the value, which
    /// is the behaviour this replaces. Reading the whole field is also what
    /// lets `stream_type_error` tell a padding or SETUP stream — both assigned,
    /// both several bytes wide — from a Type Table 2 does not assign.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let raw = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        validate_subgroup_type(raw)?;
        // Narrowing is safe: `validate_subgroup_type` has already refused
        // everything at 128 or above.
        let header_type = raw as u8;

        let track_alias = VarInt::decode_moqt::<Wire>(buf)?;
        let group_id = VarInt::decode_moqt::<Wire>(buf)?;

        let subgroup_id_mode = (header_type & SUBGROUP_ID_MODE_MASK) >> 1;
        let subgroup_id = match subgroup_id_mode {
            0 => VarInt::from_u64_moqt(0),
            2 => VarInt::decode_moqt::<Wire>(buf)?,
            // Mode 1 puts no Subgroup ID on the wire either: it is the first
            // object's ID, which this header cannot see. Store 0 until a
            // caller resolves it. Mode 3 never reaches here — the type check
            // above refuses it.
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

    /// Serialize the header exactly as its Type byte describes it.
    ///
    /// Infallible, and so willing to write a Type draft-21 Section 11.3.1
    /// tells an endpoint to reject — including a reserved-mode Type this
    /// module's own [`Self::decode`] refuses to read back. Prefer
    /// [`Self::encode_checked`], which refuses those Types instead.
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

    /// Serialize the header, refusing a Type value draft-21 forbids.
    ///
    /// Errors with [`CodecError::InvalidField`] for exactly the Types draft-21
    /// Section 11.3.1 lists as invalid (the same set [`Self::decode`] refuses),
    /// before any byte is written, so a refused header leaves `buf` untouched.
    /// Everything else is written by [`Self::encode`].
    ///
    /// The check belongs on the encode side as well as the decode side because
    /// the two halves would otherwise disagree about which streams exist: a
    /// reserved-mode header written by [`Self::encode`] cannot be read back by
    /// [`Self::decode`], and a codec used to rewrite captured traffic would
    /// emit a stream it could not then parse.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        validate_subgroup_type(self.header_type as u64)?;
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
    /// `3` never comes back from [`Self::decode`], which refuses the Types
    /// carrying it. `header_type` is a public field, so a hand-built header
    /// can still report it; [`Self::encode_checked`] is what refuses to put
    /// one on the wire.
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

/// One object within a draft-21 subgroup stream. Object IDs are
/// delta-encoded; whether a per-object "properties" block (the draft-21
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
    /// zero. `None` with a zero `payload_length` is written as
    /// [`ObjectStatus::Normal`].
    ///
    /// `None` is not "no status": every Object has one. It means the status is
    /// the one the encoding elides — [`ObjectStatus::Normal`], the only row of
    /// the Object Status registry (draft-21 Section 16.9) that permits the
    /// payload such an object carries. Decoding a payload-bearing object leaves
    /// this `None` for that reason; [`Self::status`] resolves it either way.
    ///
    /// Typed rather than a raw code. The wire field is a varint with room for
    /// any value, and draft-21 assigns three of them; the decoder refuses the
    /// rest, and this type is that same refusal on the encode side — 0x1 and
    /// 0x2 cannot be named here, so [`SubgroupObjectReader::write_object`]
    /// cannot emit a status this module's own decoder would reject.
    ///
    /// A status and a payload can be held here together, which the wire has no
    /// way to express. That combination is what draft-21's registry rules on:
    /// [`SubgroupObjectReader::write_object`] accepts it when the status is
    /// registered as permitting a payload and refuses it otherwise.
    pub object_status: Option<ObjectStatus>,
    pub payload: Vec<u8>,
}

impl SubgroupObject {
    /// The object's status, with the one draft-21's encoding elides filled in.
    ///
    /// A subgroup object states its status only when its Object Payload Length
    /// is zero. An object that carries bytes therefore has no status field, and
    /// its status is [`ObjectStatus::Normal`] — the sole row of the Object
    /// Status registry (draft-21 Section 16.9) permitting a payload, so the
    /// only status such an object could have had.
    pub fn status(&self) -> ObjectStatus {
        self.object_status.unwrap_or(ObjectStatus::Normal)
    }

    /// Whether the Object Status registry permits this object a non-empty
    /// payload, per draft-21 Section 16.9.
    ///
    /// Answered from the status alone. `payload` and `payload_length` are not
    /// consulted: on a status that permits a payload they say only whether this
    /// particular object took the offer, and on one that forbids a payload a
    /// non-empty payload is the malformation this reports, not evidence about
    /// the rule.
    pub fn permits_payload(&self) -> bool {
        self.status().permits_payload()
    }

    /// Whether this object's status is allowed to carry the properties it has.
    ///
    /// Draft-21 Section 11.1.3: "Any Object with status Normal can have
    /// properties (Section 8.4). If an endpoint receives properties on an
    /// Object with status that is not Normal, it MUST close the session with a
    /// PROTOCOL_VIOLATION."
    ///
    /// So this is `false` for exactly one shape: a non-empty properties block
    /// on an object whose status is not [`ObjectStatus::Normal`]. An object
    /// with no properties is fine at any status, and an object at Normal may
    /// carry any properties.
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
    pub fn properties_permitted(&self) -> bool {
        self.extension_headers.is_empty() || self.status() == ObjectStatus::Normal
    }
}

/// The framing of one draft-21 subgroup object, without its payload.
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
    /// What the Object Status registry says about this object's payload, or
    /// `None` if the registry has no row for its status.
    ///
    /// Draft-21 Section 16.9, Table 16 gives the registry a "Payload" column,
    /// and Section 11.1.2 makes it the rule: an Object has an empty payload
    /// unless its status is registered as permitting one. Table 16 fills the
    /// column in for the three statuses draft-21 assigns — 0x0 Normal is
    /// "Yes", 0x3 End of Group and 0x4 End of Track are "No" — and requires
    /// every future registration to fill it in too.
    ///
    /// `status` is `None` for an object whose payload length is non-zero,
    /// because the encoding puts a status field only where the payload does
    /// not go. Such an object's status is Normal, the one row permitting the
    /// payload it is carrying, so this answers
    /// [`PayloadPermission::Permitted`] rather than `None`.
    ///
    /// The `None` this does return means something else entirely: a status
    /// code with no row in the registry, for which the draft supplies no
    /// answer and this must not invent one. [`SubgroupObjectReader`] never
    /// produces such a meta — it refuses an unassigned code while decoding —
    /// but every field here is public, so a caller that assembled a meta by
    /// hand, or carried a status across from a draft numbering the set
    /// differently, can hold one.
    ///
    /// Answered from the status alone. `payload_length` is not consulted: on a
    /// status that permits a payload it says only whether this particular
    /// object took the offer, and on one that forbids a payload a non-zero
    /// length is the malformation a caller uses this to detect, not evidence
    /// about the rule.
    pub fn payload_permission(&self) -> Option<PayloadPermission> {
        match self.status {
            None => Some(ObjectStatus::Normal.payload_permission()),
            Some(code) => ObjectStatus::from_u64(code).map(ObjectStatus::payload_permission),
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
    /// A zero `payload_length` writes the object's status, with
    /// [`SubgroupObject::status`] filling in [`ObjectStatus::Normal`] when the
    /// `object_status` field is `None`. The status is typed, so every value
    /// that can reach this method is one draft-21 assigns and one
    /// [`Self::read_object`] accepts; no unassigned code can be written.
    ///
    /// Errors with [`CodecError::InvalidField`] when the Object Status registry
    /// (draft-21 Section 16.9) does not permit the object's status to carry a
    /// payload and a payload was handed over anyway. Draft-21 Section 11.1.2
    /// makes that object malformed, and the encoding has no way to state it:
    /// the status field appears only where the payload does not. Writing it
    /// would mean silently discarding one of the two — emitting the bytes as a
    /// Normal object and losing an End of Group marker, say — so it is refused
    /// instead. A status the registry does permit a payload is written as an
    /// ordinary payload object, its status implicit, since that is how the
    /// encoding spells it.
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
        // A zero declared length is also what puts a status code where the
        // payload would go, so an object carrying bytes under it is asking for
        // two framings at once.
        let declared = object.payload_length.into_inner();
        if declared != object.payload.len() as u64 {
            return Err(CodecError::InvalidField);
        }

        // The registry decides whether these two fields may be filled in at
        // once, rather than the length deciding on its own which of them gets
        // written. A status marked "Payload: No" is refused a payload; a status
        // marked "Yes" keeps it, and gets no status field on the wire because
        // the encoding elides the status of any object that carries bytes.
        // Checked alongside the length above, before any byte is emitted.
        if declared != 0 && !object.permits_payload() {
            return Err(CodecError::PayloadNotPermitted {
                status: object.status().as_u64(),
                len: object.payload.len(),
                detail: "its status is registered as forbidding one",
            });
        }

        // Properties on a non-Normal status are NOT refused here, though
        // draft-21 Section 11.1.3 forbids them. The two rules differ in kind.
        // A status beside a payload has no encoding at all — the status field
        // and the payload occupy the same position — so writing one is
        // impossible rather than merely wrong. Properties beside a status
        // encode perfectly well; the frame is well formed and non-conforming,
        // which is a judgement about what a peer may send, not about what these
        // bytes mean.
        //
        // Refusing it here would also make this writer unable to produce a
        // frame the decoder must be able to read, and the two halves of a codec
        // that disagree about which frames exist cannot be used to reproduce
        // captured traffic. [`SubgroupObject::properties_permitted`] reports
        // the violation instead, and the endpoint acts on it.

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
        if declared == 0 {
            VarInt::from_u64_moqt(object.status().as_u64()).encode_moqt::<Wire>(buf);
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
/// Bit 4. Draft-21 Section 11.2.1: "This bit is reserved and MUST be zero."
/// The opposite of Section 11.3.1, where the same bit MUST be 1.
const DATAGRAM_RESERVED_BIT: u8 = 0x10;

/// Refuse a datagram `Type Flags` value draft-21 Section 11.2.1 lists as
/// invalid.
///
/// The section states the rule twice, once in the paragraph introducing the
/// field — "If a received value has bit 4 set, or has a bit set whose meaning
/// is not specified, the endpoint MUST close the session with a
/// PROTOCOL_VIOLATION" — and once as a list of three conditions, each of which
/// MUST close the session with a PROTOCOL_VIOLATION:
///
///   1. "Values with both the STATUS bit (0x20) and END_OF_GROUP bit (0x02)
///      set": 0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E and 0x2F. The reason is
///      that an object status message cannot signal end of group — the two bits
///      ask for one datagram to be both a status and an end-of-group marker for
///      an object it does not carry.
///   2. "Values with bit 4 (0x10) set. This bit is reserved and MUST be zero."
///   3. "Values with a bit set whose meaning is not specified." Bits 0, 1, 2, 3
///      and 5 are specified; bit 6 and everything above it are not, so this
///      catches 0x40 and, with it, every value of 128 or greater.
///
/// The valid set is 0x00..0x0F and 0x20..0x2F, which is draft-19's enumeration
/// unchanged.
///
/// **These are not the subgroup header's rules.** Section 11.3.1 requires bit 4
/// to be *set*, has no unspecified-bit condition, and states an explicit
/// "values of 128 or greater" condition that this list does not need. The two
/// sets are read from their own sections and neither is derived from the other.
fn validate_datagram_type(raw: u64) -> Result<(), CodecError> {
    if datagram_type_is_valid(raw) {
        Ok(())
    } else {
        Err(datagram_type_error(raw))
    }
}

/// Every bit draft-21 Section 11.2.1 gives a datagram `Type Flags` value a
/// meaning for: PROPERTIES, END_OF_GROUP, ZERO_OBJECT_ID, DEFAULT_PRIORITY and
/// STATUS. Bit 4 is reserved and bits 6 and up are unspecified, so both fail
/// the mask.
const DATAGRAM_SPECIFIED_BITS: u64 = (DATAGRAM_PROPERTIES_BIT
    | DATAGRAM_END_OF_GROUP_BIT
    | DATAGRAM_ZERO_OBJECT_ID_BIT
    | DATAGRAM_DEFAULT_PRIORITY_BIT
    | DATAGRAM_STATUS_BIT) as u64;

/// Whether `raw` is a datagram `Type Flags` value draft-21 admits.
fn datagram_type_is_valid(raw: u64) -> bool {
    // Every bit outside the specified set fails, which covers bit 4 (reserved),
    // bit 6 (unspecified) and everything at 128 or above in one test.
    raw & !DATAGRAM_SPECIFIED_BITS == 0
        && !(raw & DATAGRAM_STATUS_BIT as u64 != 0 && raw & DATAGRAM_END_OF_GROUP_BIT as u64 != 0)
}

/// Which failure a leading datagram `Type Flags` value that is not one a reader
/// wants is.
///
/// The same split as `stream_type_error`, read against the datagram table.
/// Section 11.2.1's three conditions each get an arm, so a log names which one
/// a value fell into rather than reporting all three as one complaint; a value
/// too wide to be a one-byte flags field at all is Section 6.4.1's
/// [`CodecError::UnknownDatagramType`] instead.
///
/// The padding datagram is why the [`CodecError::InvalidField`] arm exists.
/// [`PADDING_DATAGRAM_TYPE`] is assigned, so a datagram carrying it is not
/// unknown; it simply carries no Object, and refusing it must not end the
/// session.
fn datagram_type_error(raw: u64) -> CodecError {
    if raw == PADDING_DATAGRAM_TYPE || datagram_type_is_valid(raw) {
        return CodecError::InvalidField;
    }
    if raw > 0xFF {
        return CodecError::UnknownDatagramType(raw);
    }
    let t = raw as u8;
    if t & DATAGRAM_RESERVED_BIT != 0 {
        CodecError::InvalidDatagramTypeValue {
            raw,
            detail: "bit 4 (0x10) is reserved for a datagram and must be zero",
        }
    } else if t & DATAGRAM_STATUS_BIT != 0 && t & DATAGRAM_END_OF_GROUP_BIT != 0 {
        CodecError::InvalidDatagramTypeValue {
            raw,
            detail: "it sets both the STATUS bit and the END_OF_GROUP bit",
        }
    } else {
        CodecError::InvalidDatagramTypeValue {
            raw,
            detail: "it sets a bit whose meaning is not specified for a datagram",
        }
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
    /// `None` is not "no status": a datagram whose type leaves the STATUS bit
    /// clear carries a payload, and the status of an Object that carries a
    /// payload is [`ObjectStatus::Normal`], the only row of the Object Status
    /// registry (draft-21 Section 16.9) permitting one. [`Self::status`]
    /// resolves the field either way.
    ///
    /// Typed rather than a bare byte. The wire field is one octet with 256
    /// values, and draft-21 Section 11.1.2 assigns three of them; the
    /// decoder refuses the other 253, and this type is that same refusal on
    /// the encode side — [`Self::encode`] is infallible precisely because a
    /// status it could not legally write cannot be built.
    pub object_status: Option<ObjectStatus>,
}

impl DatagramHeader {
    /// Decode a datagram header, `Type Flags` field included.
    ///
    /// The field is read as a whole varint of whatever width the sender used,
    /// and a non-minimal spelling of a valid value is accepted, for the reason
    /// given on [`SubgroupHeader::decode`] and in the module documentation.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let raw = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        validate_datagram_type(raw)?;
        // Narrowing is safe: `validate_datagram_type` has already refused every
        // value with a bit set above the specified five.
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

        // Two rules of draft-21 Section 11.2.1 reach the properties block just
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
        // such a datagram, so the endpoint is where they are enforced — the
        // same division [`SubgroupObject::properties_permitted`] explains.
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
    /// that boundary is the only thing that delimits the payload — draft-21
    /// Section 11.2.1: "There is no explicit length field for the Object
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
    /// publisher never framed as content. That is the case this refuses, and it
    /// bites hardest on a status datagram carrying the Normal code 0x0, whose
    /// status alone would report a payload as permitted.
    ///
    /// The same refusal covers a status the registry forbids a payload to, per
    /// Section 11.1.2 and the "Payload" column of Section 16.9.
    ///
    /// Errors with [`CodecError::PayloadNotPermitted`] when bytes remain and
    /// the header forbids them, naming which of the two rules refused them.
    ///
    /// # The two Properties rules are enforced here too
    ///
    /// Section 11.2.1 states them of a receiving endpoint, and this is the
    /// endpoint's read:
    ///
    /// * "If an endpoint receives a datagram with the PROPERTIES bit set and an
    ///   Properties Length of 0, it MUST close the session with a
    ///   PROTOCOL_VIOLATION." The bit and a zero length are two ways to spell
    ///   *no properties* and a datagram may use only the first, because a
    ///   datagram with none has a Type Flags value that says so and the block
    ///   costs bytes the flags already saved. A subgroup stream says the
    ///   opposite in Section 11.3.1 — there the PROPERTIES bit is fixed for the
    ///   whole stream, so an object with no properties has nowhere else to say
    ///   so and a zero-length block is the required spelling.
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
    /// [`ObjectStatus::Normal`] with the bit clear is not that case and is
    /// accepted. It is the status the encoding elides for every object that
    /// carries a payload, so stating it asks for exactly the bytes leaving it
    /// out asks for, and nothing is lost.
    ///
    /// Errors with [`CodecError::InvalidField`] on the lossy combination,
    /// before any byte is written, so a refused header leaves `buf` untouched.
    /// This is the datagram half of the rule
    /// [`SubgroupObjectReader::write_object`] applies on a subgroup stream.
    ///
    /// Also errors with [`CodecError::InvalidField`] for a Type value draft-21
    /// Section 11.2.1 lists as invalid, and for the same reason: a datagram
    /// written with one could not be read back by [`Self::decode`], and a
    /// codec whose two halves disagree about which datagrams exist cannot be
    /// used to rewrite captured traffic.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        validate_datagram_type(self.datagram_type as u64)?;
        if !self.has_status() && matches!(self.object_status, Some(s) if s != ObjectStatus::Normal)
        {
            return Err(CodecError::InvalidField);
        }
        // The two properties rules of Section 11.2.1. [`Self::decode`] reports
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
    /// clear is discarded here without a word, and a Type value draft-21
    /// forbids is written out as readily as one it assigns, including Types
    /// this module's own [`Self::decode`] refuses. Prefer
    /// [`Self::encode_checked`], which refuses both instead of resolving them.
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

    /// The datagram's object status, with the one the encoding elides filled
    /// in.
    ///
    /// A datagram states a status only when its type sets the STATUS bit, and
    /// such a datagram has no payload. One without the bit is all payload, and
    /// its status is [`ObjectStatus::Normal`] — the sole row of the Object
    /// Status registry (draft-21 Section 16.9) permitting a payload, so the
    /// only status it could have had.
    pub fn status(&self) -> ObjectStatus {
        self.object_status.unwrap_or(ObjectStatus::Normal)
    }

    /// Whether the bytes after this datagram's header are allowed to exist.
    ///
    /// Two independent rules forbid them, and this reports both:
    ///
    /// - The framing. Draft-21 Section 11.2.1: "The STATUS bit (0x20)
    ///   indicates whether the datagram contains an Object Status or Object
    ///   Payload. When set to 1, the Object Status field is present and there
    ///   is no Object Payload." A datagram that states a status has no payload
    ///   field at all, whichever status it states — so a STATUS datagram
    ///   carrying the Normal code 0x0 has no more room for bytes than one
    ///   carrying End of Group.
    /// - The status. Section 11.1.2 and the Object Status registry's
    ///   "Payload" column, Section 16.9: an Object has an empty payload unless
    ///   its status is registered as permitting one. This half reaches a
    ///   datagram whose type byte leaves the STATUS bit clear while the value
    ///   claims a status that forbids a payload — a disagreement
    ///   [`Self::encode_checked`] refuses to write, and one a decoded header
    ///   never shows.
    ///
    /// The first is the rule a decoded datagram can actually trip, and reading
    /// the registry alone misses it: `Some(ObjectStatus::Normal)` under a type
    /// byte with the STATUS bit set is exactly the case where the payload the
    /// draft says does not exist would otherwise be handed to the application
    /// as the object's content, because Normal is the one status the registry
    /// marks as permitting a payload.
    ///
    /// Distinct from [`Self::has_status`], which reports how the datagram is
    /// framed rather than whether a payload may follow. A caller holding the
    /// bytes after the header wants this one; [`Self::decode_object`] applies
    /// it for a caller who would rather the decode simply fail.
    pub fn permits_payload(&self) -> bool {
        if self.has_status() {
            return false;
        }
        self.status().permits_payload()
    }

    /// Whether this datagram's status is allowed to carry the properties it
    /// has.
    ///
    /// The same rule the subgroup form obeys. Draft-21 Section 11.2.1 builds
    /// the datagram's Properties field out of "the Object Properties structure
    /// defined in Section 11.1.3", and that section is where the rule sits:
    /// "If an endpoint receives properties on an Object with status that is not
    /// Normal, it MUST close the session with a PROTOCOL_VIOLATION."
    ///
    /// See [`SubgroupObject::properties_permitted`] for why the decoder reports
    /// this instead of refusing it.
    pub fn properties_permitted(&self) -> bool {
        self.properties.is_empty() || self.status() == ObjectStatus::Normal
    }

    /// Whether the properties block is framed the way a datagram may frame it.
    ///
    /// Draft-21 Section 11.2.1: "If an endpoint receives a datagram with the
    /// PROPERTIES bit set and an Properties Length of 0, it MUST close the
    /// session with a PROTOCOL_VIOLATION."
    ///
    /// The bit and a zero length are two ways to spell "no properties", and on
    /// a datagram they are not interchangeable: a datagram with none has a type
    /// byte that says so, and the block costs bytes the type byte already
    /// saved. This rule is the datagram's alone. A subgroup stream says the
    /// opposite in Section 11.3.1 — "Objects with no properties set Properties
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
}

// ── Fetch Header ──────────────────────────────────────────────

const FETCH_STREAM_TYPE: u64 = 0x05;

/// The head of a fetch stream: the stream type `0x05` and a Request ID.
///
/// Byte-identical to draft-19. What draft-20 widened is what the Request ID may
/// name. Section 11.4.1: "all objects on the stream belong to the track
/// requested in the message identified by Request ID", where draft-19 said "the
/// track requested in the Fetch message". The widening is deliberate, because a
/// fetch stream can
/// now be a *fill fetch stream* whose Request ID names the `SUBSCRIBE` or the
/// `REQUEST_UPDATE` that carried `FILL_PARAMETERS` (Section 3.4), not only a
/// `FETCH`. Nothing on the stream says which, so a reader that keys a fetch
/// stream by looking up a FETCH will fail to find one.
///
/// # Two things a fill fetch stream does not have, which the draft leaves open
///
/// * **No `FETCH_OK`, and therefore no `End Location` and no `End Of Track`.**
///   Section 3.4 says the fill is "delivered as a FETCH response" and
///   Section 3.4.1 says there is no `REQUEST_ERROR` for it, so there is no OK
///   either. How a subscriber learns the fill's actual end, beyond the stream
///   FINing, is unspecified; this codec treats the FIN as the only end signal
///   and does not synthesize a `FETCH_OK`. Section 9.11's rule that gaps
///   between the last Object and the FETCH_OK's Largest imply non-existence
///   cannot be applied here, because there is no FETCH_OK to read it from.
/// * **Failure is a stream reset, not an error message.** Section 3.4.1: if
///   the publisher must fail a fill it opens the stream and resets it
///   immediately after the `FETCH_HEADER`. Resetting or cancelling a fill fetch
///   stream does not affect the subscription, which keeps delivering.
///
/// Both are the caller's to act on: neither is visible in a frame.
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

/// Serialization Flags bits 0-1, the Subgroup ID encoding
/// (draft-21 Section 11.4.1.1, Table 8).
const FETCH_SUBGROUP_ID_MODE_MASK: u64 = 0x03;
/// Subgroup ID mode 0b11: an explicit Subgroup ID field is on the wire.
const FETCH_SUBGROUP_ID_EXPLICIT: u64 = 0b11;
/// Table 9 flag: an Object ID Delta field is present.
const FETCH_OBJECT_ID_DELTA_BIT: u64 = 0x04;
/// Table 9 flag: a Group ID Delta field is present.
const FETCH_GROUP_ID_DELTA_BIT: u64 = 0x08;
/// Table 9 flag: a Publisher Priority field is present.
const FETCH_PRIORITY_BIT: u64 = 0x10;
/// Table 9 flag: a Properties field is present.
const FETCH_PROPERTIES_BIT: u64 = 0x20;
/// Table 9 flag: the Object's Forwarding Preference is Datagram, so it has no
/// Subgroup ID and the two low bits are to be ignored.
const FETCH_DATAGRAM_BIT: u64 = 0x40;
/// The largest Serialization Flags value whose bits are flags. Draft-21
/// Section 11.4.1: "When less than 128, the bits represent flags".
const FETCH_FLAGS_MAX: u64 = 0x7F;
/// Table 7: End of Non-Existent Range.
const FETCH_END_OF_NON_EXISTENT_RANGE: u64 = 0x8C;
/// Table 7: End of Unknown Range.
const FETCH_END_OF_UNKNOWN_RANGE: u64 = 0x10C;
/// Table 7: End of Timed-Out Range. New in draft-20.
///
/// The minimal encoding is the two-byte `82 0C`; it is not a single byte, and
/// cannot be, because Section 11.4.1 reserves values below 128 for the bit-flag
/// reading. Its low bits are `0x0C` — Group ID Delta present, Object ID Delta
/// present — exactly as the other two markers' are, so the two fields that
/// follow occupy the ordinary delta slots of Figure 28.
const FETCH_END_OF_TIMED_OUT_RANGE: u64 = 0x20C;

/// What an End of Range indicator on a fetch stream asserts about the
/// Locations it covers, from draft-21 Section 11.4.1.2.
///
/// All three say that every Object with a Location between the previous
/// serialized Object and this one, inclusive, was not serialized. They differ
/// in why, and the three between them partition non-delivery: the publisher
/// knows the Objects are not there, it does not know either way, or it gave up
/// waiting. A subscriber can cache the first as a definitive gap and must not
/// cache the other two, so they cannot be collapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchEndOfRange {
    /// Serialization Flags 0x8C. The Objects in the range do not exist.
    ///
    /// Section 11.4.1.2: "A publisher SHOULD NOT use End of Non-Existent Range
    /// in a FETCH response except to split a range of Objects that will not be
    /// serialized into those that are known not to exist and those with unknown
    /// or timed out status." Draft-19's wording of the same sentence did not
    /// have the "or timed out" half, because it had no marker for it.
    NonExistent,
    /// Serialization Flags 0x10C. The Objects in the range have unknown
    /// status.
    Unknown,
    /// Serialization Flags 0x20C. The Objects in the range timed out: the relay
    /// abandoned them because its `FILL_TIMEOUT` budget (Section 9.20.6) ran
    /// out. **New in draft-20.**
    ///
    /// This is where a fill timeout's output goes, and it is a behavioural
    /// change as much as a new value: draft-19 classified the same Objects as
    /// Unknown gaps, so a draft-19 receiver and a draft-21 receiver reading the
    /// same relay see different markers for the same event. `FILL_TIMEOUT = 0`
    /// means the subscriber wants only immediately-available Objects and the
    /// relay MUST report everything else this way; with the parameter absent,
    /// the relay waits an implementation-specific duration first.
    TimedOut,
}

/// Which optional fields a Serialization Flags value puts on the wire.
///
/// Derived once by [`FetchObjectHeader::layout`] and then used by both
/// [`FetchObjectHeader::decode`] and [`FetchObjectHeader::encode`], so the two
/// cannot drift into disagreeing about a shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FetchObjectLayout {
    group_id_delta: bool,
    subgroup_id: bool,
    object_id_delta: bool,
    publisher_priority: bool,
    properties: bool,
}

/// One Object on a draft-21 fetch stream, up to but not including its payload.
///
/// Draft-21 Section 11.4.1 rebuilt the fetch object. Earlier drafts wrote a
/// fixed set of fields on every Object; draft-21 writes a Serialization Flags
/// varint first, and the flags say which fields follow:
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
/// Every field is optional except the flags and the payload length, and an
/// absent field means *the same as the previous Object's*, not "zero" — the
/// whole point of the layout is that a run of Objects in one group at one
/// priority costs one byte of framing each. This type therefore holds what is
/// on the wire and nothing more: the deltas, not the Group and Object IDs they
/// resolve to. Resolving them needs the previous Object on the same stream and
/// the FETCH's Group Order, neither of which a single Object header knows,
/// and Section 11.4.1 spells out the arithmetic a caller must apply:
///
///   - The first Object MUST carry both deltas, and they are the absolute
///     Group ID and Object ID.
///   - Later on, a Group ID Delta moves the group by `delta + 1` — forwards
///     under Ascending Group Order and backwards under Descending — and
///     restarts the Object ID from the Object ID Delta. With no Group ID
///     Delta, the group is unchanged and the Object ID Delta is added to the
///     previous Object's ID; with no Object ID Delta either, the Object ID is
///     the previous one plus one.
///
/// There is no Object Status field. Draft-21 Section 11.1.2 states that
/// Object Status is present only on Objects delivered via a subscription and
/// absent from Objects delivered via a FETCH, which is why this type has no
/// counterpart to [`SubgroupObject::object_status`] and why a zero
/// `payload_length` here is simply an Object with no payload.
///
/// Two Serialization Flags values name an End of Range indicator rather than
/// an Object; [`Self::end_of_range`] reports which, and Section 11.4.1.2 gives
/// the rules such a frame follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObjectHeader {
    /// The raw Serialization Flags value, kept whole rather than split into
    /// booleans because it is also the field that names an End of Range
    /// indicator, and because re-encoding must reproduce the value the
    /// publisher chose.
    pub serialization_flags: VarInt,
    /// Group ID Delta, present when the flags set 0x08. Its meaning depends on
    /// the Object's position in the stream and on the Group Order; see the
    /// type's own documentation.
    pub group_id_delta: Option<VarInt>,
    /// An explicit Subgroup ID, present only when the two low flag bits are
    /// 0b11 and the Datagram bit is clear. The other three modes derive the
    /// Subgroup ID from the previous Object and put nothing on the wire.
    pub subgroup_id: Option<VarInt>,
    /// Object ID Delta, present when the flags set 0x04. Absent means the
    /// previous Object's ID plus one.
    pub object_id_delta: Option<VarInt>,
    /// Publisher Priority, present when the flags set 0x10. Absent means the
    /// previous Object's priority.
    pub publisher_priority: Option<u8>,
    /// Raw properties bytes, excluding the byte-length prefix that precedes
    /// them on the wire, and `None` when the flags leave 0x20 clear.
    ///
    /// `Some(vec![])` and `None` are different frames: the first writes a zero
    /// length prefix, the second writes nothing at all. Opaque, like the
    /// property blocks on the subgroup and datagram forms — draft-21
    /// Section 11.4.1 defines the field as the Object Properties structure of
    /// Section 11.1.3, and these bytes are re-emitted verbatim.
    pub properties: Option<Vec<u8>>,
    /// Object Payload Length. Always on the wire; the payload itself follows
    /// this header and is not held here.
    pub payload_length: VarInt,
}

impl FetchObjectHeader {
    /// The Serialization Flags as a plain integer.
    pub fn flags(&self) -> u64 {
        self.serialization_flags.into_inner()
    }

    /// Which End of Range indicator this is, or `None` for an ordinary Object.
    ///
    /// Draft-21 Section 11.4.1, Table 7 gives the three indicators their own
    /// Serialization Flags values rather than a flag bit, so this is an
    /// equality test on the whole field and not a mask.
    ///
    /// An indicator uses the same two positions on the wire an ordinary Object
    /// uses for its deltas, and Section 11.4.1.2 says only that "the Group ID
    /// and Object ID fields are present". They are reached through
    /// [`Self::group_id_delta`] and [`Self::object_id_delta`], since those are
    /// the fields the wire has.
    ///
    /// **The ordinary delta arithmetic applies to them.** The draft does not
    /// say so: Section 11.4.1.2 states what is *absent* from a marker
    /// ("Subgroup ID, Priority and Properties are not present") and says
    /// nothing about whether the two present fields are absolute or deltas.
    /// This codec applies Section 11.4.1.1 unchanged, because the marker's
    /// flags are literally the ordinary flags — the low bits of all three
    /// markers are `0x0C`, the everyday "both deltas present" pattern — so a
    /// marker that is not the first record on the stream resolves against its
    /// predecessor exactly as an Object would. Draft-19 read them as absolute;
    /// on a first record the two readings agree, and after an Object they do
    /// not. [`FetchObjectReader`] is where the arithmetic is applied.
    pub fn end_of_range(&self) -> Option<FetchEndOfRange> {
        match self.flags() {
            FETCH_END_OF_NON_EXISTENT_RANGE => Some(FetchEndOfRange::NonExistent),
            FETCH_END_OF_UNKNOWN_RANGE => Some(FetchEndOfRange::Unknown),
            FETCH_END_OF_TIMED_OUT_RANGE => Some(FetchEndOfRange::TimedOut),
            _ => None,
        }
    }

    /// The two-bit Subgroup ID mode, `flags & 0x03`.
    ///
    /// `0b00` = the Subgroup ID is zero; `0b01` = the previous Object's
    /// Subgroup ID; `0b10` = the previous Object's Subgroup ID plus one;
    /// `0b11` = an explicit field is present. Draft-21 Section 11.4.1.1
    /// assigns all four, unlike the subgroup stream header's reserved
    /// `0b11`.
    ///
    /// Meaningless when [`Self::is_datagram`] is true: such an Object has no
    /// Subgroup ID and the section says the subscriber MUST ignore these bits.
    pub fn subgroup_id_mode(&self) -> u8 {
        (self.flags() & FETCH_SUBGROUP_ID_MODE_MASK) as u8
    }

    /// `true` when the flags set 0x40, marking an Object whose Forwarding
    /// Preference is Datagram. Such an Object has no Subgroup ID at all, so
    /// the Subgroup ID mode bits carry no meaning and no Subgroup ID field is
    /// on the wire whatever they say.
    pub fn is_datagram(&self) -> bool {
        self.flags() & FETCH_DATAGRAM_BIT != 0
    }

    /// Which optional fields `flags` puts on the wire, or
    /// [`CodecError::InvalidField`] if draft-21 does not define that
    /// Serialization Flags value.
    ///
    /// Section 11.4.1 defines the field in two pieces: values below 128 are a
    /// set of flags, and Table 7 adds exactly three values above that — 0x8C,
    /// 0x10C and draft-20's new 0x20C. "Any other value is a
    /// PROTOCOL_VIOLATION", which is what the error covers — every value at 128
    /// or above that is not one of the three.
    ///
    /// The three indicators get their layout from Section 11.4.1.2 rather than
    /// from their bits: "the Group ID and Object ID fields are present.
    /// Subgroup ID, Priority and Properties are not present." Their low bits
    /// happen to spell exactly that (all three are `0x0C` in the low seven
    /// bits: Group ID Delta and Object ID Delta set, Subgroup ID mode 0b00, no
    /// priority, no properties), but that is a property of the values the draft
    /// chose and not a rule, so the layout is taken from the section that
    /// states it.
    ///
    /// **`Object Payload Length` is present on a marker, encoded as 0.**
    /// Section 11.4.1.2 lists what is absent and does not name it, and Figure
    /// 28 marks it mandatory; the draft does not settle the case. This codec
    /// keeps the field, because omitting one a figure requires is what
    /// desynchronises a fetch stream, and a marker has nothing to put in it
    /// anyway. The layout below therefore differs from an ordinary object only
    /// in the optional fields.
    fn layout(flags: u64) -> Result<FetchObjectLayout, CodecError> {
        if flags == FETCH_END_OF_NON_EXISTENT_RANGE
            || flags == FETCH_END_OF_UNKNOWN_RANGE
            || flags == FETCH_END_OF_TIMED_OUT_RANGE
        {
            return Ok(FetchObjectLayout {
                group_id_delta: true,
                subgroup_id: false,
                object_id_delta: true,
                publisher_priority: false,
                properties: false,
            });
        }
        if flags > FETCH_FLAGS_MAX {
            return Err(CodecError::InvalidField);
        }
        Ok(FetchObjectLayout {
            group_id_delta: flags & FETCH_GROUP_ID_DELTA_BIT != 0,
            // An Object with the Datagram bit set has no Subgroup ID to write,
            // whatever the mode bits hold, so the field is absent.
            subgroup_id: flags & FETCH_DATAGRAM_BIT == 0
                && flags & FETCH_SUBGROUP_ID_MODE_MASK == FETCH_SUBGROUP_ID_EXPLICIT,
            object_id_delta: flags & FETCH_OBJECT_ID_DELTA_BIT != 0,
            publisher_priority: flags & FETCH_PRIORITY_BIT != 0,
            properties: flags & FETCH_PROPERTIES_BIT != 0,
        })
    }

    /// Decode one fetch object header, leaving the payload in `buf`.
    ///
    /// Errors with [`CodecError::InvalidField`] for a Serialization Flags
    /// value draft-21 Section 11.4.1 does not define, and with
    /// [`CodecError::UnexpectedEnd`] or a varint error when the buffer runs
    /// out mid-field.
    ///
    /// The flags are validated before any field is read, because they are what
    /// says where the fields are: decoding an undefined value would mean
    /// picking a layout the draft never described and then consuming a
    /// plausible number of bytes under it.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let serialization_flags = VarInt::decode_moqt::<Wire>(buf)?;
        let layout = Self::layout(serialization_flags.into_inner())?;

        let group_id_delta =
            layout.group_id_delta.then(|| VarInt::decode_moqt::<Wire>(buf)).transpose()?;
        let subgroup_id =
            layout.subgroup_id.then(|| VarInt::decode_moqt::<Wire>(buf)).transpose()?;
        let object_id_delta =
            layout.object_id_delta.then(|| VarInt::decode_moqt::<Wire>(buf)).transpose()?;

        let publisher_priority = if layout.publisher_priority {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        } else {
            None
        };

        let properties = if layout.properties {
            let len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
            Some(crate::types::read_bytes(buf, len)?)
        } else {
            None
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

    /// Serialize the header, refusing one whose fields disagree with its own
    /// Serialization Flags.
    ///
    /// Errors with [`CodecError::InvalidField`] when the flags are a value
    /// draft-21 does not define, and when any optional field is present while
    /// its flag is clear or absent while its flag is set. Checked before any
    /// byte is written, so a refused header leaves `buf` untouched.
    ///
    /// Fallible for the same reason [`DatagramHeader::encode_checked`] is: the
    /// flags decide the framing, so writing them as the authority and dropping
    /// whatever they do not cover is silent data loss. A Group ID Delta held
    /// with the 0x08 bit clear is not written, the reader takes the Object as
    /// belonging to the previous Object's group, and nothing about the
    /// resulting stream looks wrong. The mirror case is worse: a flag set with
    /// no value behind it would have to invent one, and an invented Object ID
    /// Delta of zero is a real Object ID.
    ///
    /// Nothing here checks the deltas against the previous Object — that no
    /// Object other than the first may reference a prior Object that does not
    /// exist, for one. A single header has no way to see that, and this type
    /// deliberately does not carry stream state.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let layout = Self::layout(self.flags())?;
        if layout.group_id_delta != self.group_id_delta.is_some()
            || layout.subgroup_id != self.subgroup_id.is_some()
            || layout.object_id_delta != self.object_id_delta.is_some()
            || layout.publisher_priority != self.publisher_priority.is_some()
            || layout.properties != self.properties.is_some()
        {
            return Err(CodecError::InvalidField);
        }

        self.serialization_flags.encode_moqt::<Wire>(buf);
        // Wire order, from Figure 27: Group ID Delta, then Subgroup ID, then
        // Object ID Delta. The `layout` check above has already established
        // that exactly the fields the flags call for are present, so whichever
        // of the three are `Some` are the ones that belong here.
        for field in
            [self.group_id_delta, self.subgroup_id, self.object_id_delta].into_iter().flatten()
        {
            field.encode_moqt::<Wire>(buf);
        }
        if let Some(priority) = self.publisher_priority {
            buf.put_u8(priority);
        }
        if let Some(properties) = &self.properties {
            VarInt::from_usize(properties.len()).encode_moqt::<Wire>(buf);
            buf.put_slice(properties);
        }
        self.payload_length.encode_moqt::<Wire>(buf);
        Ok(())
    }
}

/// The order a FETCH response's Groups arrive in, which decides how a Group ID
/// Delta is applied.
///
/// Draft-21 Section 11.4.1.1: "If the Group Order is Ascending, the Group ID is
/// the prior Object's Group ID plus the Group ID Delta + 1. If the Group Order
/// is Descending, the Group ID is the prior Object's Group ID minus the (Group
/// ID Delta + 1)."
///
/// The order is not on the data stream — it is settled by the control exchange
/// that opened the FETCH, whose GROUP_ORDER parameter (Section 9.20.9) spells
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
    /// Section 11.4.1.2: "Prior Priority: The Priority from the last actual
    /// Object before the End of Range indicator."
    ///
    /// The draft-21 fallback for a subscription that never stated a priority is
    /// left to the caller rather than substituted here, so that "no frame has
    /// said" stays distinguishable from "a frame said 128".
    pub publisher_priority: Option<u8>,
}

/// Resolves the delta-encoded fields of the frames on one FETCH stream.
///
/// Draft-21 Section 11.4.1.1 defines nearly every field of a fetch frame
/// against "the prior Object", so no frame after the first can be understood on
/// its own. This holds what the frames so far established, in the two parts the
/// draft keeps separate: Section 11.4.1.2 says that after an End of Range
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
    /// Section 11.4.1.1 states:
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

        // An End of Range marker carries no Subgroup ID and no Priority, so
        // those two are resolved here rather than by the rules below: Section
        // 11.4.1.2 says the prior Subgroup ID and prior Priority for whatever
        // follows come "from the last actual Object before the End of Range
        // indicator", which means a marker neither states them nor disturbs
        // them, and a marker arriving before any Object has none to report.
        //
        // Its two present fields go through the ordinary arithmetic below. The
        // draft does not say they do — see [`FetchObjectHeader::end_of_range`]
        // for why this codec reads them that way and where draft-19 differed.
        let is_marker = header.end_of_range().is_some();

        let group_id = match (self.prior_location, header.group_id_delta) {
            // The first object's delta is its absolute Group ID.
            (None, Some(delta)) => delta.into_inner(),
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
                // A Group ID Delta restarts the Object ID from its own delta,
                // which is why a new group does not continue the previous
                // group's numbering.
                (_, true, Some(delta)) => delta.into_inner(),
                (Some((_, prior_object)), false, Some(delta)) => {
                    prior_object.checked_add(delta.into_inner()).ok_or(CodecError::InvalidField)?
                }
                (Some((_, prior_object)), _, None) => {
                    prior_object.checked_add(1).ok_or(CodecError::InvalidField)?
                }
                (None, _, _) => return Err(CodecError::InvalidField),
            };

        if is_marker {
            self.prior_location = Some((group_id, object_id));
            return Ok(FetchObject {
                header,
                group_id,
                subgroup_id: None,
                object_id,
                publisher_priority: self.prior_publisher_priority,
            });
        }

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
                // Mode 0b11, the only value left: the field is on the wire.
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
/// same frames. Removing a frame changes what the frames after it are encoded
/// *against*, and draft-21 Section 11.4.1.1 defines nearly every field against
/// "the prior Object", so the survivor that follows a removed run cannot keep
/// its original bytes. What has to change is not one field: an Object that
/// carried no Group ID Delta because it shared its predecessor's group needs
/// one once that predecessor is gone, so a field appears and a flag bit with
/// it.
///
/// # Why this is not a general encoder
///
/// Every frame it writes came off a stream, so the caller already holds the
/// frame's own [`FetchObjectHeader`] alongside the resolved values. That header
/// is used as the preference: wherever the original shape still encodes the
/// same meaning against the new predecessor, it is kept, so a stream with
/// nothing removed from it is reproduced byte for byte. Only where the original
/// shape would now decode to something else is a different one chosen. An
/// encoder built from the resolved values alone could not do that — it would
/// have to invent a canonical form and would rewrite every frame on a stream
/// that needed no rewriting at all.
///
/// # What it refuses
///
/// [`CodecError::InvalidField`] where no encoding exists rather than picking
/// one: a Group ID that moves against the FETCH's Group Order, an Object ID
/// that does not advance, an Object with neither a Subgroup ID nor the Datagram
/// bit, and the arithmetic overflows. Each of these is a frame this writer was
/// handed that no draft-21 stream could carry, and inventing a value for it
/// would put a different Object on the wire than the one it was given.
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
    /// that does both. Separated so that a caller can measure the bytes a
    /// re-encode would take before committing to it.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] for a frame that cannot be encoded against
    /// the current predecessor; see the type's own documentation for the list.
    pub fn header_for(&self, frame: &FetchObject) -> Result<FetchObjectHeader, CodecError> {
        let original = &frame.header;

        // An End of Range marker carries no Subgroup ID, Priority or
        // Properties, and its flags are a fixed Table 7 value rather than
        // something derived from which fields are present — so only the two
        // identity fields are re-derived, through the same arithmetic an
        // ordinary Object uses. The mirror of the reader; see
        // [`FetchObjectHeader::end_of_range`] for why the arithmetic applies at
        // all, and note the consequence: a marker after a removed run does not
        // keep its original bytes, which is precisely what draft-19's
        // absolute reading would have got wrong.
        if original.end_of_range().is_some() {
            let (group_id_delta, object_id_delta) = self.identity_fields(frame, original)?;
            // Table 7's three values all carry the low bits `0x0C`, so a
            // marker's flags fix both fields as present and there is no shorter
            // form to fall back on. A marker whose Group ID matches its
            // predecessor's therefore has no encoding at all: the Group ID
            // Delta moves the group by `delta + 1` and cannot stand still.
            // `identity_fields` answers `None` for a field the ordinary rules
            // would leave off, which is exactly that case, and it is refused
            // rather than written as an absolute value the reader would resolve
            // against its predecessor.
            let (Some(group_id_delta), Some(object_id_delta)) = (group_id_delta, object_id_delta)
            else {
                return Err(CodecError::InvalidField);
            };
            return Ok(FetchObjectHeader {
                serialization_flags: original.serialization_flags,
                group_id_delta: Some(group_id_delta),
                subgroup_id: None,
                object_id_delta: Some(object_id_delta),
                publisher_priority: None,
                properties: None,
                payload_length: original.payload_length,
            });
        }

        let (group_id_delta, object_id_delta) = self.identity_fields(frame, original)?;
        let (subgroup_mode, subgroup_id) = self.subgroup_field(frame, original)?;
        let publisher_priority = self.priority_field(frame, original)?;

        let mut flags = subgroup_mode;
        if original.is_datagram() {
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
        if original.properties.is_some() {
            flags |= FETCH_PROPERTIES_BIT;
        }

        Ok(FetchObjectHeader {
            serialization_flags: VarInt::from_u64(flags)?,
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
    /// one. Only the Object ID Delta has a choice to make, and it is made in
    /// favour of the shape the frame arrived in.
    fn identity_fields(
        &self,
        frame: &FetchObject,
        original: &FetchObjectHeader,
    ) -> Result<(Option<VarInt>, Option<VarInt>), CodecError> {
        let Some((prior_group, prior_object)) = self.prior_location else {
            // Section 11.4.1.1: "The first Object MUST include a Group ID Delta
            // and Object ID Delta, and these values are the absolute Group ID
            // and Object ID."
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
            // is a byte shorter. Section 11.4.1.1: "If Object ID Delta is not
            // present, the Object ID is the prior Object's ID plus one,
            // REGARDLESS OF WHICH GROUP IT BELONGS TO." So an Object that
            // continues the numbering into a new group encodes without one —
            // the Object ID does not restart at the group boundary unless a
            // delta says so.
            //
            // Gated on the frame's own framing, like the same-group case below,
            // so re-emitting a stream reproduces the publisher's bytes instead
            // of silently rewriting the shorter form into the longer one. It
            // also keeps markers correct without a special case: Table 7's
            // three values all carry the low bits `0x0C`, so a marker always
            // arrives with an Object ID Delta and never takes this branch —
            // which matters, because the marker path above requires both fields
            // to be `Some` and refuses the frame otherwise.
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
    /// their Subgroup ID keeps inheriting it and its bytes do not move. Only
    /// when the predecessor changed under it does a different mode get chosen,
    /// and then the cheapest one that says the right number.
    fn subgroup_field(
        &self,
        frame: &FetchObject,
        original: &FetchObjectHeader,
    ) -> Result<(u64, Option<VarInt>), CodecError> {
        // Section 11.4.1.1 has the subscriber ignore these bits on a
        // Datagram-forwarded Object, and no field is on the wire whatever they
        // say, so the frame's own bits are carried across untouched.
        if original.is_datagram() {
            return Ok((original.flags() & FETCH_SUBGROUP_ID_MODE_MASK, None));
        }

        let subgroup_id = frame.subgroup_id.ok_or(CodecError::InvalidField)?;
        let inherits = self.prior_subgroup_id == Some(subgroup_id);
        let successor =
            self.prior_subgroup_id.is_some_and(|p| p.checked_add(1) == Some(subgroup_id));

        // The frame's own mode, kept when it still names this number.
        let kept = match original.flags() & FETCH_SUBGROUP_ID_MODE_MASK {
            0x00 if subgroup_id == 0 => Some((0x00, None)),
            0x01 if inherits => Some((0x01, None)),
            0x02 if successor => Some((0x02, None)),
            FETCH_SUBGROUP_ID_EXPLICIT => Some((FETCH_SUBGROUP_ID_EXPLICIT, Some(subgroup_id))),
            _ => None,
        };
        let (mode, explicit) = match kept {
            Some(pair) => pair,
            None if subgroup_id == 0 => (0x00, None),
            None if inherits => (0x01, None),
            None if successor => (0x02, None),
            None => (FETCH_SUBGROUP_ID_EXPLICIT, Some(subgroup_id)),
        };
        Ok((mode, explicit.map(VarInt::from_u64).transpose()?))
    }

    /// The Publisher Priority field, or `None` when the predecessor already
    /// carries it.
    ///
    /// Written whenever the frame wrote one, so a publisher that stated a
    /// priority on every Object keeps its bytes, and written anyway when the
    /// predecessor's differs or when there is no predecessor to inherit from.
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
    /// bytes and is the caller's to copy, unchanged — nothing about it depends
    /// on what preceded the Object.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] for a frame with no encoding against the
    /// current predecessor. The writer is left untouched when this happens, so
    /// a caller that gives up on one frame and carries on with the next is
    /// writing against the same predecessor it thought it was.
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
    /// Split from the write so that a caller re-emitting bytes it already holds
    /// can advance without producing a header twice — which is what happens
    /// whenever the framing a frame arrived in still encodes the same meaning
    /// against the frame before it, and is why this is public.
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
    /// `test-vectors/transport/draft21/codec/data-streams/subgroup.json`.
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

    /// An object carrying both `payload` and, in the caller's hands, `status`.
    /// The wire has no room for both, which is what the registry rules on.
    fn payload_object(status: Option<ObjectStatus>, payload: Vec<u8>) -> SubgroupObject {
        SubgroupObject {
            object_id: vi(0),
            extension_headers: Vec::new(),
            payload_length: vi(payload.len() as u64),
            object_status: status,
            payload,
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

    /// Every status draft-21 assigns can be written and read back as the same
    /// status, on both a subgroup stream and a status datagram.
    ///
    /// The set is read from `ObjectStatus::ALL` — the three rows of the Object
    /// Status registry — rather than restated here, so this moves with the
    /// draft if a code is ever reassigned. It is the gate on typing the two
    /// `object_status` fields: a typed field that silently narrowed or
    /// renumbered the set would fail here even though it still compiled.
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
    /// This is a gate on the status code points only. Which of those statuses
    /// may carry a payload is the separate question
    /// [`the_registry_decides_which_statuses_may_carry_a_payload`] gates.
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
    /// encoder the `0x2` that this module's decoder is documented as refusing,
    /// so no test here can watch one be refused. Reverting
    /// `DatagramHeader::object_status` to `Option<u8>` with an `unwrap_or(0)`
    /// encoder does not make this test fail — it makes it stop compiling,
    /// which is the guarantee:
    ///
    /// ```text
    /// error[E0308]: mismatched types
    ///     = note: expected enum `Option<u8>`
    ///                found enum `Option<draft21::types::ObjectStatus>`
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

    // ── The registry's payload column ───────────────────────

    /// Draft-21 Section 16.9, Table 16, "Payload" column: Normal "Yes", End of
    /// Group "No", End of Track "No".
    ///
    /// Restated here rather than read from [`ObjectStatus::payload_permission`]
    /// so the gate holds its own copy of the registry. A codec that changed a
    /// row would still agree with itself; only a second copy notices.
    const PAYLOAD_COLUMN: &[(ObjectStatus, bool)] = &[
        (ObjectStatus::Normal, true),
        (ObjectStatus::EndOfGroup, false),
        (ObjectStatus::EndOfTrack, false),
    ];

    /// Which statuses may carry a payload is decided by the registry, not by a
    /// payload length.
    ///
    /// Draft-18 states one blanket rule — an Object with any status other than
    /// Normal has an empty payload — so under it the answer can be read off the
    /// status number, or equivalently off a zero payload length. Draft-21
    /// Section 11.1.2 replaces the blanket rule with "an Object MUST have an
    /// empty payload unless its Object Status value is registered as permitting
    /// a payload", the permission being a column of the Object Status registry
    /// in Section 16.9. The three rows assigned today give the same answers
    /// draft-18's rule gives; what this gate observes is that the answers come
    /// from the rows.
    ///
    /// Each row is driven both ways. A zero-length object with that status must
    /// encode and read back — Normal included, since it permits a payload
    /// without requiring one and so has to stay expressible with none. An
    /// object handed a payload under that status must be accepted exactly when
    /// the row permits one, and otherwise refused with nothing written.
    ///
    /// # What this catches, observed by making each change and running it
    ///
    /// Dropping the registry check from `write_object`, leaving the length to
    /// decide on its own — an End of Group object with a payload is then
    /// written as a plain payload object and its status is gone:
    ///
    /// ```text
    /// write_object must refuse a payload under EndOfGroup, which the registry forbids one; got Ok(())
    /// ```
    ///
    /// Moving End of Group into the permitting column, as a status registered
    /// later with "Payload: Yes" would be:
    ///
    /// ```text
    /// assertion `left == right` failed: decoded EndOfGroup reports the wrong payload permission
    ///   left: true
    ///  right: false
    /// ```
    ///
    /// Letting the permission pick the framing as well as govern it — writing
    /// the status field for the statuses that forbid a payload instead of for
    /// the objects whose payload length is zero, which is the wrong reading of
    /// the registry and the one that costs the zero-length Normal object its
    /// encoding, since the draft frames the status on payload length alone:
    ///
    /// ```text
    /// read_object refused a zero-length Normal: VarInt(UnexpectedEnd)
    /// ```
    #[test]
    fn the_registry_decides_which_statuses_may_carry_a_payload() {
        let header = SubgroupHeader::decode(&mut &hex("100100800004deadbeef")[..]).unwrap();
        assert_eq!(
            PAYLOAD_COLUMN.len(),
            ObjectStatus::ALL.len(),
            "every assigned status needs a row in the payload column"
        );

        for &(status, permitted) in PAYLOAD_COLUMN {
            assert!(ObjectStatus::ALL.contains(&status), "{status:?} is not an assigned status");

            // A zero-length object is legal under every row, and is the only
            // framing that states a status on a subgroup stream.
            let mut empty = Vec::new();
            SubgroupObjectReader::new(&header)
                .write_object(&status_object(Some(status)), &mut empty)
                .unwrap_or_else(|e| panic!("write_object refused a zero-length {status:?}: {e:?}"));
            let object = SubgroupObjectReader::new(&header)
                .read_object(&mut &empty[..])
                .unwrap_or_else(|e| panic!("read_object refused a zero-length {status:?}: {e:?}"));
            assert_eq!(object.status(), status, "zero-length {status:?} lost its status");
            assert!(object.payload.is_empty(), "zero-length {status:?} gained a payload");
            assert_eq!(
                object.permits_payload(),
                permitted,
                "decoded {status:?} reports the wrong payload permission"
            );

            // A status datagram is the one carrier where the registry is not
            // the last word. Section 11.2.1 puts the status field in the
            // payload's place — "When set to 1, the Object Status field is
            // present and there is no Object Payload" — so no status makes
            // trailing bytes part of such a datagram, Normal included, and
            // `permitted` is not the expected answer here.
            let datagram = DatagramHeader::decode(&mut &status_datagram(status.as_u64())[..])
                .unwrap_or_else(|e| panic!("datagram decode refused {status:?}: {e:?}"));
            assert!(
                !datagram.permits_payload(),
                "a status datagram has no Object Payload field, so {status:?} permits no bytes"
            );
            assert_eq!(
                datagram.status().permits_payload(),
                permitted,
                "decoded {status:?} datagram reports the wrong registry row"
            );
            let mut whole = status_datagram(status.as_u64());
            whole.extend_from_slice(&hex("deadbeef"));
            let trailing = DatagramHeader::decode_object(&mut &whole[..]);
            assert!(
                matches!(trailing, Err(CodecError::PayloadNotPermitted { .. })),
                "trailing bytes on a {status:?} status datagram must be refused; got {trailing:?}"
            );

            // The same status, handed a payload the wire cannot frame beside it.
            let mut written = Vec::new();
            let result = SubgroupObjectReader::new(&header)
                .write_object(&payload_object(Some(status), hex("deadbeef")), &mut written);

            if permitted {
                result.unwrap_or_else(|e| {
                    panic!(
                        "write_object refused a payload under {status:?}, \
                         which the registry permits: {e:?}"
                    )
                });
                let object = SubgroupObjectReader::new(&header)
                    .read_object(&mut &written[..])
                    .unwrap_or_else(|e| {
                        panic!("read_object refused its own output for {status:?}: {e:?}")
                    });
                assert_eq!(object.payload, hex("deadbeef"), "{status:?} lost its payload");
                assert_eq!(object.status(), status, "{status:?} came back as another status");
            } else {
                assert!(
                    matches!(result, Err(CodecError::PayloadNotPermitted { .. })),
                    "write_object must refuse a payload under {status:?}, \
                     which the registry forbids one; got {result:?}"
                );
                assert!(written.is_empty(), "a refused {status:?} object still wrote {written:?}");
            }
        }

        // A datagram without the STATUS bit is all payload, and the status its
        // framing leaves out is the one row that permits a payload.
        let plain = DatagramHeader::decode(&mut &[0x00u8, 0x01, 0x00, 0x00, 0x80][..])
            .expect("a datagram with no status field must decode");
        assert_eq!(plain.status(), ObjectStatus::Normal);
        assert!(plain.permits_payload(), "a payload-carrying datagram must be permitted one");
    }
}

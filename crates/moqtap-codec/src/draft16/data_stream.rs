//! Draft-16 data stream header encoding and decoding.
//!
//! Draft-16 subgroup type-byte flag layout:
//! - `& 0x01`: extensions present on objects
//! - `& 0x06`: SUBGROUP_ID_MODE. Section 10.4.2: "The SUBGROUP_ID_MODE field
//!   (bits 1-2, mask 0x06) is a two-bit field that determines the encoding of
//!   the Subgroup ID. To extract this value, perform a bitwise AND with mask
//!   0x06 and right-shift by 1 bit". Mode 0 puts no Subgroup ID on the wire
//!   and it is zero, mode 1 takes it from the first object, mode 2 reads it as
//!   a field after the Group ID, and mode 3 is reserved
//! - `& 0x08`: end-of-group marker
//! - `& 0x20`: no publisher_priority (0x30+ types)
//!
//! Because the mode is one field and not two independent bits, the three
//! carriers are mutually exclusive: a Type setting both `0x02` and `0x04` names
//! the reserved mode, not two carriers at once. This module described those bits
//! separately and read them separately, which let a single Type answer to two
//! carriers.
//!
//! Draft-15 spells the same three carriers out of the same two bits, as a pair
//! of table columns rather than a named field, and the two drafts end up
//! admitting the same twenty-four Types — draft-16 by excluding the reserved
//! mode from the ranges `0x10`-`0x1F` and `0x30`-`0x3F`, draft-15 by listing
//! them.
//!
//! Draft-16 datagram type-byte flag layout:
//! - `0x01`: extensions present (byte-length-prefixed blob)
//! - `0x02`: end-of-group
//! - `0x04`: no object_id (object_id = 0 implied)
//! - `0x08`: default priority (priority omitted, inherited)
//! - `0x20`: status datagram (carries object_status instead of payload)
//!
//! Draft-16 fetch objects are framed differently again: a per-object
//! Serialization Flags varint decides which of Group ID, Subgroup ID, Object ID,
//! Priority and Extensions are on the wire, and a field left off is taken from
//! the object before it. See [`FetchObjectHeader`] for the flag layout and
//! [`FetchObjectReader`] for the inheritance. A fetch object carries no Object
//! Status at all — draft-16 Section 10.2.1.1 puts that field on subscription
//! deliveries only.
//!
//! Extension headers in draft-16 are byte-length-prefixed opaque blobs
//! (not count-prefixed as in draft-14).

use super::types::ObjectStatus;
use crate::error::CodecError;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Advance `buf` past `len` bytes without copying them.
fn skip(buf: &mut impl Buf, len: u64) -> Result<(), CodecError> {
    let len = usize::try_from(len).map_err(|_| CodecError::UnexpectedEnd)?;
    if buf.remaining() < len {
        return Err(CodecError::UnexpectedEnd);
    }
    buf.advance(len);
    Ok(())
}

/// Turn a wire Object Status code into the status draft-16 gives it, refusing
/// any code the draft does not assign.
///
/// Draft-16 Section 10.2.1.1 lists the codes an object may carry and says any
/// other value SHOULD be treated as a protocol error and the session closed
/// with a PROTOCOL_VIOLATION. Every place this module reads a status runs the
/// wire code through here. Draft-16 is where the set narrowed to three: 0x1,
/// which drafts 07-15 assign to Object Does Not Exist, is refused here.
///
/// [`SubgroupObject::object_status`] and [`DatagramHeader::object_status`]
/// then store the [`ObjectStatus`] this returns rather than the raw code, so
/// the refusal is not something a future decode site can forget: those fields
/// cannot hold an unassigned value at all, in either direction, and the encode
/// paths need no check of their own.
/// [`SubgroupObjectMeta::status`] deliberately keeps the raw code — it is a
/// decode-only view that never feeds an encoder — but it is filtered through
/// here too, so the two readers agree byte for byte on what parses.
fn decoded_status(code: u64) -> Result<ObjectStatus, CodecError> {
    ObjectStatus::from_u64(code).ok_or(CodecError::InvalidField)
}

/// Whether an Object at `status` is allowed to carry `extensions_len` bytes of
/// extension headers.
///
/// Draft-16 Section 10.2.1.2: "Any Object with status Normal can have extension
/// headers", with a reference to Section 2.5 inside the sentence, and "If an
/// endpoint receives extension headers on Objects with status that is not
/// Normal, it MUST close the session with a PROTOCOL_VIOLATION."
///
/// Draft-16 is the draft where the status set narrowed to Normal, End of Group
/// and End of Track, so the rule reaches two codes rather than the single
/// "Object Does Not Exist" earlier drafts name, draft-15 Section 10.2.1.1 among
/// them. It reaches every carrier that can announce a status: an Object on a
/// subgroup stream and a status datagram. An Object on a fetch stream carries
/// no status field on this draft — Section 10.2.1.1 puts the field on
/// subscription deliveries only — so it is the one carrier that cannot break
/// the rule.
///
/// So this is `false` for exactly one shape: a non-empty extension block on an
/// Object whose status is not Normal. An Object with no extensions is fine at
/// any status, and an Object at Normal may carry any extensions.
///
/// `status` is taken as a raw code so the two subgroup readers can share this:
/// one resolves the status into [`ObjectStatus`] and the other keeps the wire
/// code. `None` means the Object carried a payload, which is Normal by
/// definition and always permitted.
///
/// # Why the readers do not apply this themselves
///
/// A deliberate contrast with the payload rule beside it. A status next to a
/// payload has no encoding — the status field and the payload occupy the same
/// position on the wire — so a writer refuses that pair as unrepresentable.
/// Extensions next to a status encode perfectly well: the block sits between
/// the extensions length and the status field and reads back byte for byte. The
/// frame is well formed and merely non-conforming, which is a judgement about
/// what a peer may send, not about what the bytes mean.
///
/// A decoder that refused it could not report the violation, and a writer that
/// refused it could not reproduce a capture containing one — including the
/// committed `subgroup-extensions-status-object` vector, which is exactly this
/// frame. The rule addresses an endpoint *receiving* such an Object, so the
/// endpoint is where it is enforced. This predicate is what it asks.
fn extensions_permitted_at(status: Option<u64>, extensions_len: u64) -> bool {
    match status {
        None => true,
        Some(code) => extensions_len == 0 || code == ObjectStatus::Normal.as_u64(),
    }
}

// ── Subgroup and datagram Type validation ─────────────────────
//
// Both Types are read as a single byte rather than as a varint. Every Type
// draft-16 assigns to either is below 0x40, which is exactly the one-byte range
// of the varint encoding this draft uses, and both forms independently forbid
// bits 6 and 7 — so a first byte that begins a longer varint is a Type the
// draft rules out anyway.
//
// Reading a full varint and narrowing it to `u8` was the defect: a Type of
// 0x110, spelled as the two-byte varint 0x41 0x10, truncated to 0x10 and was
// accepted as a valid subgroup header. An out-of-range Type aliased onto a
// valid one instead of being refused, and the stream behind it was parsed under
// framing its sender never asked for.

/// Bit 4, which every subgroup header Type sets.
const SUBGROUP_BASE_BIT: u8 = 0x10;
/// Bits 6 and 7, which the subgroup header's 0b00X1XXXX form leaves clear.
///
/// Narrower than the equivalent on draft-19, whose form is 0b0XX1XXXX and which
/// therefore admits 0x50..0x5F and 0x70..0x7F as well. Draft-16 Section 10.4.2
/// names only "the ranges 0x10..0x1F and 0x30..0x3F".
const SUBGROUP_FORM_FORBIDDEN_BITS: u8 = 0xC0;
/// Bits 1-2, the SUBGROUP_ID_MODE field.
const SUBGROUP_ID_MODE_MASK: u8 = 0x06;
/// The SUBGROUP_ID_MODE value draft-16 reserves, once the mask is applied and
/// the field shifted down.
const SUBGROUP_ID_MODE_RESERVED: u8 = 0b11;

/// Refuse a subgroup header Type value draft-16 Section 10.4.2 lists as invalid.
///
/// The section gives two lists and says of both that an endpoint receiving a
/// stream header with such a Type MUST close the session with a
/// PROTOCOL_VIOLATION:
///
///   - "Type values with SUBGROUP_ID_MODE set to 0b11: 0x16, 0x17, 0x1E, 0x1F,
///     0x36, 0x37, 0x3E, 0x3F. This mode is reserved for future use."
///   - "Type values that do not match the form 0b00X1XXXX (i.e., Type values
///     outside the ranges 0x10..0x1F and 0x30..0x3F, or values where bit 4 is
///     not set)."
///
/// The reserved mode is worth separating from a merely unassigned code point,
/// because it is not decodable rather than merely unknown. The other three modes
/// each say whether a Subgroup ID field follows the Group ID; 0b11 says nothing,
/// so a decoder has to guess, and a wrong guess shifts every later field by the
/// width of that varint. This module read those eight Types as though an
/// explicit Subgroup ID were present, which turned a header the draft says to
/// reject into objects with plausible, wrong contents.
///
/// Which of the two lists a Type failed is what `stream_type_error` reports,
/// and the answer is not the same error: one is a Type no table assigns and the
/// other is a Type this draft assigns a form to and then forbids.
fn validate_subgroup_type(raw: u64) -> Result<(), CodecError> {
    if subgroup_type_is_valid(raw) {
        Ok(())
    } else {
        Err(stream_type_error(raw))
    }
}

/// The unidirectional stream Type draft-16 Section 10.4.4 gives a fetch stream.
const FETCH_STREAM_TYPE: u64 = 0x05;

/// Refuse a Type field spelled in more than one byte, before anything narrows
/// it to a byte.
///
/// Returns `Ok(None)` when the next Type is a single byte and the caller should
/// read it itself, `Ok(Some(err))` when it is wider and `refusal` has named the
/// failure, and `Err` only when the buffer does not hold the whole field yet.
///
/// Every Type draft-16 assigns is below 0x40 and so occupies one byte under
/// this draft's variable-length integer encoding. A wider spelling is therefore
/// one of two things, and neither may be read as a header: a Type this draft
/// does not assign, or a non-minimal spelling of one it does. The second is the
/// dangerous one — narrowing a two-byte 0x4001 to its low octet turns it into
/// the assigned Type 0x01, so a peer could name any Type it liked and have it
/// parsed as another.
///
/// The full varint is decoded before `refusal` sees it, so the refusal reports
/// the number the field actually carried rather than its first byte.
fn wide_type_refusal(
    buf: &mut impl Buf,
    refusal: fn(u64) -> CodecError,
) -> Result<Option<CodecError>, CodecError> {
    if !buf.has_remaining() {
        return Err(CodecError::UnexpectedEnd);
    }
    // Under the draft-16 encoding the top two bits of the first byte give the
    // field's length, so a first byte below 0x40 is the whole of it.
    if buf.chunk()[0] < 0x40 {
        return Ok(None);
    }
    let raw = VarInt::decode(buf)?.into_inner();
    Ok(Some(refusal(raw)))
}

/// The refusal a datagram Type deserves, as a plain function so
/// `wide_type_refusal` can take it.
fn datagram_type_refusal(raw: u64) -> CodecError {
    match validate_datagram_type(raw) {
        Ok(()) => CodecError::InvalidField,
        Err(e) => e,
    }
}

/// Whether `raw` is a subgroup Type draft-16 admits: inside the form, and not
/// the reserved SUBGROUP_ID_MODE.
fn subgroup_type_is_valid(raw: u64) -> bool {
    raw <= 0xFF && {
        let t = raw as u8;
        t & SUBGROUP_FORM_FORBIDDEN_BITS == 0
            && t & SUBGROUP_BASE_BIT != 0
            && (t & SUBGROUP_ID_MODE_MASK) >> 1 != SUBGROUP_ID_MODE_RESERVED
    }
}

/// Whether `raw` sits inside the subgroup form but names the reserved
/// SUBGROUP_ID_MODE — the first of Section 10.4.2's two lists.
fn subgroup_type_is_reserved_mode(raw: u64) -> bool {
    raw <= 0xFF && {
        let t = raw as u8;
        t & SUBGROUP_FORM_FORBIDDEN_BITS == 0
            && t & SUBGROUP_BASE_BIT != 0
            && (t & SUBGROUP_ID_MODE_MASK) >> 1 == SUBGROUP_ID_MODE_RESERVED
    }
}

/// Which failure a leading unidirectional stream Type that is not the one a
/// reader wants is.
///
/// Draft-16 states two rules about such a Type and answers both with a close,
/// and telling them apart is the whole job of this function.
///
/// Section 10 is about the table: "An endpoint that receives an unknown stream
/// or datagram type MUST close the session." A Type the table does not assign
/// is [`CodecError::UnknownStreamType`]. The table has two entries — 0x05 for
/// FETCH_HEADER and the subgroup form — because draft-16 carries its control
/// messages on a bidirectional stream and defines no padding stream, so
/// FETCH_HEADER is the only assigned value a subgroup reader can be handed.
///
/// Section 10.4.2 is about the subgroup form specifically, and the eight Types
/// inside it that name the reserved SUBGROUP_ID_MODE. Those are not unknown —
/// the form is assigned and the draft lists the values outright — but they are
/// unreadable, and they are [`CodecError::InvalidTypeValue`].
///
/// A fetch stream at the subgroup reader is neither. The value is one this
/// draft defines, the disagreement is with the reader that was called, and the
/// session survives it.
fn stream_type_error(raw: u64) -> CodecError {
    if raw == FETCH_STREAM_TYPE || subgroup_type_is_valid(raw) {
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

/// The END_OF_GROUP bit of a datagram Type.
const DATAGRAM_END_OF_GROUP_BIT: u8 = 0x02;
/// The STATUS bit of a datagram Type.
const DATAGRAM_STATUS_BIT: u8 = 0x20;
/// Bits 4, 6 and 7, which the datagram's 0b00X0XXXX form leaves clear.
const DATAGRAM_FORM_FORBIDDEN_BITS: u8 = 0xD0;

/// Refuse a datagram Type value draft-16 Section 10.3.1 lists as invalid.
///
/// The section gives two lists and says of both that an endpoint receiving a
/// datagram with such a Type MUST close the session with a PROTOCOL_VIOLATION:
///
///   - "Type values with both the STATUS bit (0x20) and END_OF_GROUP bit (0x02)
///     set: 0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F. An object status
///     message cannot signal end of group."
///   - "Type values that do not match the form 0b00X0XXXX (i.e., Type values
///     outside the ranges 0x00..0x0F and 0x20..0x2F)."
///
/// That leaves 24 of the 256 byte values valid. Without this check every other
/// one is accepted, and bit 4 is the bit that separates a datagram Type from a
/// subgroup stream header Type — so an unchecked datagram Type could name a
/// stream header and be parsed as a datagram anyway.
///
/// The two lists are not the same failure. A Type outside the form is one no
/// table assigns, and so is [`CodecError::UnknownDatagramType`]; a Type inside
/// the form setting STATUS and END_OF_GROUP together is one this draft names
/// and forbids, and so is [`CodecError::InvalidTypeValue`].
fn validate_datagram_type(raw: u64) -> Result<(), CodecError> {
    if datagram_type_is_valid(raw) {
        Ok(())
    } else if datagram_type_is_status_end_of_group(raw) {
        Err(CodecError::InvalidTypeValue {
            raw,
            detail: "it sets both the STATUS bit and the END_OF_GROUP bit",
        })
    } else {
        Err(CodecError::UnknownDatagramType(raw))
    }
}

/// Whether `raw` is a datagram Type draft-16 admits.
fn datagram_type_is_valid(raw: u64) -> bool {
    raw <= 0xFF && {
        let t = raw as u8;
        t & DATAGRAM_FORM_FORBIDDEN_BITS == 0
            && !(t & DATAGRAM_STATUS_BIT != 0 && t & DATAGRAM_END_OF_GROUP_BIT != 0)
    }
}

/// Whether `raw` sits inside the datagram form but sets STATUS and END_OF_GROUP
/// together — the first of Section 10.3.1's two lists.
fn datagram_type_is_status_end_of_group(raw: u64) -> bool {
    raw <= 0xFF && {
        let t = raw as u8;
        t & DATAGRAM_FORM_FORBIDDEN_BITS == 0
            && t & DATAGRAM_STATUS_BIT != 0
            && t & DATAGRAM_END_OF_GROUP_BIT != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupHeader {
    pub header_type: u8,
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub subgroup_id: VarInt,
    pub publisher_priority: Option<u8>,
}

impl SubgroupHeader {
    pub fn has_extensions(&self) -> bool {
        self.header_type & 0x01 != 0
    }

    /// Whether SUBGROUP_ID_MODE is 1: the Subgroup ID is the first object's
    /// Object ID and is not transmitted on the wire.
    ///
    /// Reads the two bits as the one field Section 10.4.2 defines, rather than
    /// as the single bit `0x02`. The single-bit reading answered `true` for a
    /// Type naming the reserved mode 3, where `0x02` and `0x04` are both set —
    /// so this predicate and [`Self::has_explicit_subgroup_id`] answered `true`
    /// together, for a state one two-bit field cannot be in.
    pub fn subgroup_id_from_first_object(&self) -> bool {
        (self.header_type & SUBGROUP_ID_MODE_MASK) >> 1 == 1
    }

    /// Whether SUBGROUP_ID_MODE is 2: an explicit Subgroup ID field follows the
    /// Group ID.
    ///
    /// [`Self::decode`] refuses the reserved mode before reading any field, so
    /// on a decoded header this agrees with the single-bit `0x04` reading it
    /// replaces. The two differ only on a header built by hand, which is the
    /// only way to hold a reserved-mode Type at all.
    pub fn has_explicit_subgroup_id(&self) -> bool {
        (self.header_type & SUBGROUP_ID_MODE_MASK) >> 1 == 2
    }

    pub fn has_end_of_group(&self) -> bool {
        self.header_type & 0x08 != 0
    }

    pub fn has_priority(&self) -> bool {
        self.header_type & 0x20 == 0
    }

    /// Serialize the header exactly as its Type byte describes it.
    ///
    /// Infallible, and so willing to write a Type draft-16 Section 10.4.2 tells
    /// an endpoint to reject — including a reserved-mode Type this module's own
    /// [`Self::decode`] refuses to read back. Prefer [`Self::encode_checked`],
    /// which refuses those Types instead.
    ///
    /// A reserved-mode Type gets no Subgroup ID field, because mode 3 defines
    /// none: the draft says what the other three modes put on the wire and
    /// nothing about this one. Writing the field there was an artifact of
    /// reading `0x04` on its own, and it disagreed with every neighbouring
    /// draft — 15, 17, 18 and 19 all leave it off.
    ///
    /// Every field is driven by the Type byte, because that is the only thing
    /// [`Self::decode`] and the peer have to go on — the Priority byte
    /// included. Driving that one off `publisher_priority` being `Some`
    /// instead desyncs the stream: a Type with DEFAULT_PRIORITY (`0x20`) set
    /// beside a `Some` writes a stray byte the reader takes for the first
    /// Object's Object ID Delta, and a Type with the bit clear beside a `None`
    /// leaves the reader taking that Delta for the priority. Either way every
    /// later field shifts — which is precisely the disagreement
    /// [`Self::encode_checked`]'s doc comment says this pair must not have.
    ///
    /// A `None` under a Type whose bit is clear therefore writes 128 rather
    /// than dropping the byte. Draft-16 Section 11.1.1.1: "A subscription has
    /// Publisher Priorty 128 if this extension is omitted", so 128 is this
    /// draft's own name for an unstated priority and not an invented filler.
    /// Drafts 17-20 write the same value in the same place. Use
    /// [`Self::encode_checked`] to be told about the disagreement rather than
    /// having it resolved silently.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.header_type as usize).encode(buf);
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        if self.has_explicit_subgroup_id() {
            self.subgroup_id.encode(buf);
        }
        if self.has_priority() {
            buf.put_u8(self.publisher_priority.unwrap_or(128));
        }
    }

    /// Serialize the header, refusing a Type value draft-16 forbids.
    ///
    /// Errors with [`CodecError::InvalidField`] for exactly the Types Section
    /// 10.4.2 lists as invalid — the same set [`Self::decode`] refuses — before
    /// any byte is written, so a refused header leaves `buf` untouched.
    ///
    /// The check belongs on this side as well because the two halves would
    /// otherwise disagree about which streams exist: a reserved-mode header
    /// written by [`Self::encode`] cannot be read back by [`Self::decode`], and
    /// a codec used to rewrite captured traffic would emit a stream it could not
    /// then parse.
    ///
    /// That argument covers the Priority byte too. `publisher_priority`
    /// disagreeing with the Type byte's DEFAULT_PRIORITY bit (`0x20`) is the
    /// same failure one field along: a header that does not mean what it says,
    /// whose bytes the peer reads under framing its writer never asked for.
    /// [`Self::encode`] does not desync the stream over it — the byte follows
    /// the Type byte — but resolving the disagreement is not the same as being
    /// told about it, and the caller who set the wrong half is the only one who
    /// can fix it. Same check, same reason, as draft-15 Section 10.4.2's
    /// encoder.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        validate_subgroup_type(self.header_type as u64)?;
        if self.has_priority() != self.publisher_priority.is_some() {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
    }

    /// Decode a subgroup header, Type field included.
    ///
    /// A Type spelled in more than one byte is refused before it is narrowed,
    /// by `wide_type_refusal`. Every Type draft-16 assigns fits a single
    /// byte, so a wider spelling is either a Type this draft does not have or a
    /// non-minimal spelling of one it does, and both have to be refused rather
    /// than truncated into a Type that happens to be valid.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        if let Some(err) = wide_type_refusal(buf, stream_type_error)? {
            return Err(err);
        }
        let header_type = buf.get_u8();
        validate_subgroup_type(header_type as u64)?;
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        // `validate_subgroup_type` has already refused the reserved mode, so
        // the field is read for mode 2 and for nothing else. Reading the mask
        // rather than the `0x04` bit makes that independent of the check above
        // instead of contingent on it.
        let subgroup_id = if (header_type & SUBGROUP_ID_MODE_MASK) >> 1 == 2 {
            VarInt::decode(buf)?
        } else {
            VarInt::from_usize(0)
        };
        let publisher_priority = if header_type & 0x20 == 0 {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        } else {
            None
        };
        Ok(Self { header_type, track_alias, group_id, subgroup_id, publisher_priority })
    }
}

/// One object within a draft-16 subgroup stream with its Object ID
/// already resolved from the delta encoding. See
/// [`SubgroupObjectReader`] for stateful encode/decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupObject {
    pub object_id: VarInt,
    /// Raw extension-header bytes, excluding the byte-length prefix that
    /// precedes them on the wire. Empty when the stream header does not
    /// set the extensions-present bit, or when the block is present but
    /// zero-length. Opaque: [`SubgroupObjectReader::write_object`] re-emits
    /// the prefix and these bytes verbatim.
    pub extension_headers: Vec<u8>,
    pub payload_length: VarInt,
    /// Object status; `Some` when `payload_length == 0`.
    ///
    /// The wire field is a varint, so it can carry any value up to 2^62-1;
    /// draft-16 Section 10.2.1.1 assigns three of them and says a peer SHOULD
    /// treat the rest as a protocol error. This field is typed to the assigned
    /// set, so it refuses to hold the codes the draft leaves unassigned —
    /// including 0x1, Object Does Not Exist, which drafts 07-15 assign and
    /// draft-16 dropped. That makes the refusal a property of the struct
    /// rather than of any one code path: an encoder cannot be handed a status
    /// the draft does not define, and does not have to check.
    ///
    /// `None` on a zero-length object means the same thing as
    /// [`ObjectStatus::Normal`] and encodes as it; the wire field is not
    /// optional once `payload_length` is zero.
    pub object_status: Option<ObjectStatus>,
    pub payload: Vec<u8>,
}

impl SubgroupObject {
    /// The status this Object resolves to.
    ///
    /// The wire carries a status field only on a zero-length Object, so an
    /// Object holding bytes is [`ObjectStatus::Normal`] whatever
    /// [`Self::object_status`] says — draft-16 Section 10.2.1.1: "This status is
    /// implicit for any non-zero length object."
    pub fn status(&self) -> ObjectStatus {
        if self.payload_length.into_inner() == 0 {
            self.object_status.unwrap_or(ObjectStatus::Normal)
        } else {
            ObjectStatus::Normal
        }
    }

    /// Whether this Object's status is allowed to carry the extension headers
    /// it has.
    ///
    /// `false` for exactly one shape: a non-empty extension block on an Object
    /// whose status is not [`ObjectStatus::Normal`]. See
    /// `extensions_permitted_at` for the rule and for why neither
    /// [`SubgroupObjectReader::read_object`] nor
    /// [`SubgroupObjectReader::write_object`] applies it — this is the codec's
    /// way of reporting the violation to the endpoint that must act on it,
    /// rather than refusing bytes that are well formed.
    pub fn extensions_permitted(&self) -> bool {
        extensions_permitted_at(
            self.object_status.map(|s| s.as_u64()),
            self.extension_headers.len() as u64,
        )
    }
}

/// Whether an Object carrying a given status is allowed a non-empty payload.
///
/// Draft-16 Section 10.2.1.1 states the rule in one sentence — "Any object with
/// a status code other than zero MUST have an empty payload" — and the same
/// section makes Normal (0x0) "implicit for any non-zero length object". So the
/// permission follows from the status code alone, with no payload length in
/// hand, which is what makes it worth naming: a caller that has only an
/// object's framing can ask whether the bytes it is about to forward are
/// allowed there at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadPermission {
    /// The status permits a payload but does not require one: a zero-length
    /// object with such a status is well formed, and draft-16's encodings can
    /// spell it.
    Permitted,
    /// An object with such a status has an empty payload, and one carrying
    /// bytes is malformed.
    Forbidden,
}

impl PayloadPermission {
    /// `true` for [`PayloadPermission::Permitted`].
    pub fn permits(self) -> bool {
        matches!(self, PayloadPermission::Permitted)
    }
}

/// The framing of one draft-16 subgroup object, without its payload.
///
/// Produced by [`SubgroupObjectReader::read_object_meta`] for callers that
/// forward an object's bytes verbatim and never inspect the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubgroupObjectMeta {
    /// Resolved absolute Object ID.
    pub object_id: u64,
    /// Byte length of the extension-header block's contents, excluding its
    /// length prefix.
    pub extension_headers_len: u64,
    /// Declared payload length. Zero when `status` is `Some`.
    pub payload_length: u64,
    /// Object status wire code, present only when the payload is empty.
    ///
    /// Kept as the raw code, unlike [`SubgroupObject::object_status`]: a meta
    /// is produced by [`SubgroupObjectReader::read_object_meta`] and is never
    /// an encode input, and a relay that reads a status on one draft may hand
    /// it to a draft that numbers the same value differently. The code is
    /// still one draft-16 assigns — `read_object_meta` refuses the others.
    pub status: Option<u64>,
    /// Total bytes this object occupies on the wire, prefix fields included.
    pub wire_len: u64,
}

impl SubgroupObjectMeta {
    /// Whether draft-16 allows this object a non-empty payload, or `None` when
    /// the answer does not exist.
    ///
    /// Draft-16 Section 10.2.1.1 gives the rule for the three codes it assigns:
    /// Normal (0x0) permits a payload, and "any object with a status code other
    /// than zero MUST have an empty payload", which covers End of Group (0x3)
    /// and End of Track (0x4). No status at all means the object carried bytes
    /// — the status field is on the wire only when `payload_length` is zero —
    /// and the same section makes Normal "implicit for any non-zero length
    /// object", so that case answers [`PayloadPermission::Permitted`] as well.
    ///
    /// `None` is reserved for a `status` the draft does not assign. A meta read
    /// off the wire cannot hold one — [`SubgroupObjectReader::read_object_meta`]
    /// refuses those bytes — but the field is public and holds the raw code
    /// precisely so a value carried over from another draft's numbering can sit
    /// in it. Draft-16 states no payload rule for a code it never assigned, and
    /// there is no safe direction to guess in: answering `Permitted` would wave
    /// through a payload the peer may have to reject, and `Forbidden` would
    /// discard one the peer may accept.
    pub fn payload_permission(&self) -> Option<PayloadPermission> {
        match self.status {
            None => Some(PayloadPermission::Permitted),
            Some(code) => match ObjectStatus::from_u64(code)? {
                ObjectStatus::Normal => Some(PayloadPermission::Permitted),
                ObjectStatus::EndOfGroup | ObjectStatus::EndOfTrack => {
                    Some(PayloadPermission::Forbidden)
                }
            },
        }
    }

    /// Whether this Object's status is allowed to carry the extension block it
    /// declares.
    ///
    /// The meta form of [`SubgroupObject::extensions_permitted`], answering
    /// from the declared block length rather than its contents, so a relay that
    /// forwards bytes verbatim can report the violation without copying the
    /// block.
    pub fn extensions_permitted(&self) -> bool {
        extensions_permitted_at(self.status, self.extension_headers_len)
    }
}

/// Stateful reader/writer for draft-16 subgroup objects. Mirrors the
/// draft-15 semantics (delta-encoded object IDs and header-typed
/// extension presence).
#[derive(Debug, Clone)]
pub struct SubgroupObjectReader {
    extensions_present: bool,
    prev_object_id: Option<u64>,
}

impl SubgroupObjectReader {
    pub fn new(header: &SubgroupHeader) -> Self {
        Self { extensions_present: header.has_extensions(), prev_object_id: None }
    }

    pub fn read_object(&mut self, buf: &mut impl Buf) -> Result<SubgroupObject, CodecError> {
        let delta = VarInt::decode(buf)?.into_inner();
        // The first object's field is its absolute Object ID; every later
        // object encodes the gap to its predecessor, biased by one because
        // two objects on a subgroup stream cannot share an ID.
        let object_id_val = match self.prev_object_id {
            None => delta,
            Some(prev) => prev
                .checked_add(1)
                .and_then(|v| v.checked_add(delta))
                .ok_or(CodecError::InvalidField)?,
        };
        self.prev_object_id = Some(object_id_val);
        let object_id = VarInt::from_u64(object_id_val).map_err(|_| CodecError::InvalidField)?;

        // Draft-16: extensions are a byte-length-prefixed opaque blob.
        let extension_headers = if self.extensions_present {
            let ext_len = VarInt::decode(buf)?.into_inner() as usize;
            crate::types::read_bytes(buf, ext_len)?
        } else {
            Vec::new()
        };

        let payload_length_vi = VarInt::decode(buf)?;
        let payload_length_val = payload_length_vi.into_inner() as usize;
        let (object_status, payload) = if payload_length_val == 0 {
            let status = decoded_status(VarInt::decode(buf)?.into_inner())?;
            (Some(status), Vec::new())
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
            let code = VarInt::decode(buf)?.into_inner();
            decoded_status(code)?;
            Some(code)
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
    /// Errors with [`CodecError::InvalidField`] when `object.object_id` is
    /// not strictly greater than the previously written object's ID, since
    /// no valid delta exists for that case.
    ///
    /// A zero `payload_length` makes this a status object, and the status
    /// field is then mandatory on the wire: an absent
    /// [`SubgroupObject::object_status`] is written as
    /// [`ObjectStatus::Normal`]. The code written is always one draft-16
    /// assigns, because the field cannot hold any other, so the bytes this
    /// produces are always bytes [`SubgroupObjectReader::read_object`] accepts.
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

        // Extensions on a non-Normal status are NOT refused here, though
        // Section 10.2.1.2 forbids them. The two rules differ in kind. A status
        // beside a payload has no encoding at all — the status field and the
        // payload occupy the same position — so writing one is impossible
        // rather than merely wrong. Extensions beside a status encode perfectly
        // well; the frame is well formed and non-conforming, which is a
        // judgement about what a peer may send, not about what these bytes
        // mean.
        //
        // Refusing it here would also make this writer unable to reproduce a
        // frame the decoder must be able to read, including the committed
        // `subgroup-extensions-status-object` vector.
        // [`SubgroupObject::extensions_permitted`] reports the violation
        // instead, and the endpoint acts on it.

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
            let ext_len = object.extension_headers.len();
            VarInt::from_usize(ext_len).encode(buf);
            buf.put_slice(&object.extension_headers);
        }
        object.payload_length.encode(buf);
        if object.payload_length.into_inner() == 0 {
            // Zero-length means a status object, and the status is not
            // optional on the wire; an unset one is Normal.
            let status = object.object_status.unwrap_or(ObjectStatus::Normal);
            VarInt::from_usize(status.as_u64() as usize).encode(buf);
        } else {
            buf.put_slice(&object.payload);
        }
        self.prev_object_id = Some(oid);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramHeader {
    pub datagram_type: u8,
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub object_id: VarInt,
    /// Publisher priority — `None` when the DEFAULT_PRIORITY flag is set and
    /// the priority is inherited from the subscription's control message.
    pub publisher_priority: Option<u8>,
    /// Opaque extension-headers blob (only when flag 0x01 is set).
    pub extension_headers: Vec<u8>,
    /// Object status (only when the `0x20` status flag is set).
    ///
    /// The wire field is a varint and can carry any value up to 2^62-1;
    /// draft-16 Section 10.2.1.1 assigns three of them and says a peer SHOULD
    /// treat the rest as a protocol error. This field is typed to the assigned
    /// set, so it cannot hold 0x1, 0x2 or anything from 0x5 up —
    /// [`Self::encode`] therefore needs no check and cannot emit a datagram
    /// that [`Self::decode`] would reject.
    ///
    /// `None` while the status flag is set encodes as
    /// [`ObjectStatus::Normal`]: once the flag is set the field is present on
    /// the wire, so there is nothing for `None` to mean but the default.
    pub object_status: Option<ObjectStatus>,
}

impl DatagramHeader {
    pub fn has_extensions(&self) -> bool {
        self.datagram_type & 0x01 != 0
    }

    pub fn is_end_of_group(&self) -> bool {
        self.datagram_type & 0x02 != 0
    }

    pub fn has_object_id(&self) -> bool {
        self.datagram_type & 0x04 == 0
    }

    /// When set, publisher_priority is omitted on the wire and inherited
    /// from the subscription / control-message context.
    pub fn has_default_priority(&self) -> bool {
        self.datagram_type & 0x08 != 0
    }

    pub fn is_status(&self) -> bool {
        self.datagram_type & 0x20 != 0
    }

    /// Whether this datagram's status is allowed to carry the extension headers
    /// it has.
    ///
    /// The same rule the subgroup form obeys — draft-16 Section 10.3.1 builds
    /// the datagram's Extensions field out of the structure Section 10.2.1.2
    /// defines, and that section is where the rule sits. See
    /// [`SubgroupObject::extensions_permitted`] for why [`Self::decode`]
    /// reports this instead of refusing it.
    ///
    /// The block is on the wire only when the type byte sets the EXTENSIONS
    /// bit, so contents held here with the bit clear are not written and do not
    /// count against the rule.
    pub fn extensions_permitted(&self) -> bool {
        extensions_permitted_at(
            self.object_status.map(|s| s.as_u64()),
            if self.has_extensions() { self.extension_headers.len() as u64 } else { 0 },
        )
    }

    /// Encode the datagram header, refusing a status the framing cannot carry.
    ///
    /// A datagram states a status only when its type byte sets the STATUS bit
    /// (0x20). With the bit clear there is no status field on the wire, so an
    /// `object_status` of anything but [`ObjectStatus::Normal`] has nowhere to
    /// go: [`Self::encode`] drops it, and the datagram parses back as an
    /// ordinary payload object. An End of Group marker written that way does
    /// not arrive late or malformed — it does not arrive at all, and the
    /// receiver sees a normal object in its place.
    ///
    /// Draft-16 Section 10.3.1 puts the framing side plainly — "The STATUS bit
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
    /// Errors with [`CodecError::InvalidField`] on the lossy combination,
    /// before any byte is written, so a refused header leaves `buf` untouched.
    ///
    /// Three further refusals, each of them a datagram this codec would
    /// otherwise emit and then decline to read back:
    ///
    /// * A Type value Section 10.3.1 lists as invalid. See
    ///   `validate_datagram_type`.
    /// * An EXTENSIONS bit set over an empty extension block. Section 10.3.1:
    ///   "If an endpoint receives a datagram with the EXTENSIONS bit set and an
    ///   Extension Headers Length of 0, it MUST close the session with a
    ///   PROTOCOL_VIOLATION." [`Self::encode`] writes the length prefix from the
    ///   block's own length, so it spells exactly the datagram the peer must
    ///   close the session over. This is a datagram rule only: on a subgroup
    ///   stream the same section says "Objects with no extensions set Extension
    ///   Headers Length to 0", because the Type byte is fixed for the whole
    ///   stream and an Object with no extensions has no other way to say so.
    /// * Extensions on an Object whose status is not Normal (Section 10.2.1.2).
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        validate_datagram_type(self.datagram_type as u64)?;
        if !self.is_status() && matches!(self.object_status, Some(s) if s != ObjectStatus::Normal) {
            return Err(CodecError::InvalidField);
        }
        if self.has_extensions() && self.extension_headers.is_empty() {
            return Err(CodecError::InvalidField);
        }
        // Section 10.2.1.2. [`Self::decode`] reports this rather than refusing
        // it, because the datagram it describes is well framed and a codec that
        // could not read one could not reproduce a capture containing it.
        // Writing one is the other direction and has no such excuse: a
        // conforming peer answers with a PROTOCOL_VIOLATION, so emitting one
        // costs the session and not merely the datagram.
        if !self.extensions_permitted() {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
    }

    /// Encode the datagram header to `buf`.
    ///
    /// When the type byte sets the status flag the status field is written
    /// unconditionally, defaulting to [`ObjectStatus::Normal`]. Omitting it
    /// would truncate the datagram: [`Self::decode`] reads a status whenever
    /// the flag is set, and answers [`CodecError::UnexpectedEnd`] when the
    /// bytes stop first.
    ///
    /// The type byte is taken as the authority on framing, which is what makes
    /// this infallible — and what makes it lossy when the struct disagrees with
    /// itself. An `object_status` set while the type byte leaves the STATUS bit
    /// clear is discarded here without a word. Prefer [`Self::encode_checked`],
    /// which refuses that combination instead of resolving it.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.datagram_type as usize).encode(buf);
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        if self.has_object_id() {
            self.object_id.encode(buf);
        }
        if !self.has_default_priority() {
            buf.put_u8(self.publisher_priority.unwrap_or(128));
        }
        if self.has_extensions() {
            VarInt::from_usize(self.extension_headers.len()).encode(buf);
            buf.put_slice(&self.extension_headers);
        }
        if self.is_status() {
            let status = self.object_status.unwrap_or(ObjectStatus::Normal);
            VarInt::from_usize(status.as_u64() as usize).encode(buf);
        }
    }

    /// Decode a datagram header, Type field included.
    ///
    /// A Type spelled in more than one byte is refused first, for the reason
    /// given on [`SubgroupHeader::decode`].
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        if let Some(err) = wide_type_refusal(buf, datagram_type_refusal)? {
            return Err(err);
        }
        let datagram_type = buf.get_u8();
        validate_datagram_type(datagram_type as u64)?;
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let object_id =
            if datagram_type & 0x04 == 0 { VarInt::decode(buf)? } else { VarInt::from_usize(0) };
        let publisher_priority = if datagram_type & 0x08 != 0 {
            None
        } else {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        };
        let extension_headers = if datagram_type & 0x01 != 0 {
            let ext_len = VarInt::decode(buf)?.into_inner() as usize;
            // A datagram whose type says extensions are present must actually carry
            // some: receiving one with an Extension Headers Length of 0 closes the
            // session. The opposite holds on a subgroup stream, where the type byte is
            // fixed for the whole stream and an object with no extensions has no other
            // way to say so, which is why this check belongs to the datagram readers
            // alone.
            if ext_len == 0 {
                return Err(CodecError::InvalidField);
            }
            crate::types::read_bytes(buf, ext_len)?
        } else {
            Vec::new()
        };
        let object_status = if datagram_type & 0x20 != 0 {
            Some(decoded_status(VarInt::decode(buf)?.into_inner())?)
        } else {
            None
        };
        Ok(Self {
            datagram_type,
            track_alias,
            group_id,
            object_id,
            publisher_priority,
            extension_headers,
            object_status,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchHeader {
    pub request_id: VarInt,
}

impl FetchHeader {
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(FETCH_STREAM_TYPE as usize).encode(buf);
        self.request_id.encode(buf);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let stream_type = VarInt::decode(buf)?.into_inner();
        if stream_type != FETCH_STREAM_TYPE {
            return Err(stream_type_error(stream_type));
        }
        let request_id = VarInt::decode(buf)?;
        Ok(Self { request_id })
    }
}

/// The two Serialization Flags values draft-16 gives a meaning of their own
/// instead of reading as a bit field, from Section 10.4.4 Table 4.
///
/// The bits of Serialization Flags are flags only "when less than 128"; Table 4
/// assigns two larger values, and of everything else at or above 128 the
/// section says "Any other value is a PROTOCOL_VIOLATION". That is why
/// [`FetchObjectHeader::decode`] refuses an unassigned large value outright
/// rather than carrying it through as an unknown flag word — there is no
/// framing to parse behind it.
///
/// Both markers stand in for a span of Objects rather than one: Section 10.4.4.2
/// reads them as covering every Location between the previous serialized
/// Object, if any, and this one, inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FetchEndOfRange {
    /// End of Non-Existent Range (0x8C): every Object in the covered span is
    /// known not to exist. Section 10.4.4.2 adds that a publisher SHOULD NOT
    /// use this except to split a span it will not serialize into the part
    /// known absent and the part whose status is unknown.
    NonExistent = 0x8c,
    /// End of Unknown Range (0x10C): the status of every Object in the covered
    /// span is unknown.
    Unknown = 0x10c,
}

impl FetchEndOfRange {
    /// Both values Table 4 assigns, in ascending wire order.
    ///
    /// This is exactly the set [`FetchEndOfRange::from_u64`] accepts above the
    /// flag range.
    pub const ALL: &[FetchEndOfRange] = &[FetchEndOfRange::NonExistent, FetchEndOfRange::Unknown];

    /// The Table 4 meaning of `v`, or `None` when `v` is a flag word (anything
    /// below 128) or a large value the table leaves unassigned.
    ///
    /// The two answers `None` covers are not the same thing, and callers must
    /// not merge them: a flag word is ordinary framing, an unassigned large
    /// value is a protocol violation. [`FetchObjectHeader::decode`] separates
    /// them by testing the 128 boundary itself.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x8c => Some(FetchEndOfRange::NonExistent),
            0x10c => Some(FetchEndOfRange::Unknown),
            _ => None,
        }
    }

    /// Return the wire value.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

/// How an Object on a draft-16 fetch stream states its Subgroup ID.
///
/// The two least significant bits of Serialization Flags form this field;
/// draft-16 Section 10.4.4.1 Table 5 lists the four readings. Three of them put
/// no Subgroup ID on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchSubgroupMode {
    /// 0x00 — the Subgroup ID is zero.
    Zero,
    /// 0x01 — the Subgroup ID is the prior Object's Subgroup ID.
    SameAsPrior,
    /// 0x02 — the Subgroup ID is the prior Object's Subgroup ID plus one.
    PriorPlusOne,
    /// 0x03 — the Subgroup ID field is present on the wire.
    Present,
}

/// One Object as it is framed on a draft-16 fetch stream, before any field is
/// resolved against the Object before it.
///
/// Draft-16 Section 10.4.4 Figure 31 gives the layout: a Serialization Flags
/// varint, then Group ID, Subgroup ID, Object ID, Publisher Priority and
/// Extensions, each present only when the flags say so, then an Object Payload
/// Length and the payload itself. Every optional field here is `Some` exactly
/// when its bytes were on the wire, so [`Self::encode`] can put back the same
/// bytes [`Self::decode`] took off — including the difference between an absent
/// extensions block and a present, zero-length one.
///
/// The payload is not part of this struct: `payload_length` bytes follow it on
/// the stream. That mirrors [`SubgroupObjectMeta`], and it is what lets a relay
/// that forwards bytes verbatim read the framing without copying the payload.
///
/// Two things separate this from the fetch object of drafts 07-13. There is no
/// Object Status field — Section 10.2.1.1 says the status "is only present in
/// objects that are delivered via a SUBSCRIPTION, and is absent in Objects
/// delivered via a FETCH" — so a zero `payload_length` is simply an empty
/// object, with no status varint behind it. And the fields that are present are
/// absolute: the flags decide presence, and Table 5 and Table 6 decide what an
/// absent field inherits, but a field that is on the wire carries its own value
/// rather than a delta. Draft-16 spells "Object ID Delta" out by name where it
/// means one, on subgroup streams; Figure 31 says "Object ID".
///
/// Resolving the absent fields needs the Object before this one, which a single
/// header does not have. [`FetchObjectReader`] carries that state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObjectHeader {
    /// Serialization Flags exactly as they appeared on the wire: a flag word
    /// below 128, or one of the [`FetchEndOfRange`] markers.
    pub serialization_flags: VarInt,
    /// Group ID, when the flags put it on the wire.
    pub group_id: Option<VarInt>,
    /// Subgroup ID, present only under [`FetchSubgroupMode::Present`].
    pub subgroup_id: Option<VarInt>,
    /// Object ID, when the flags put it on the wire.
    pub object_id: Option<VarInt>,
    /// Publisher Priority, when the flags put it on the wire.
    pub publisher_priority: Option<u8>,
    /// Raw extension-header bytes, excluding the byte-length prefix that
    /// precedes them on the wire, and `None` when the flags carry no extensions
    /// block at all. Opaque: [`Self::encode`] re-emits the prefix and these
    /// bytes verbatim. The block's own shape is the one Section 10.2.1.2
    /// defines for every draft-16 object.
    pub extensions: Option<Vec<u8>>,
    /// Declared Object Payload Length. The payload follows on the stream and is
    /// not held here.
    pub payload_length: VarInt,
}

impl FetchObjectHeader {
    /// Serialization Flags as a plain integer.
    fn flags(&self) -> u64 {
        self.serialization_flags.into_inner()
    }

    /// The Table 4 marker this object is, or `None` when its Serialization
    /// Flags are an ordinary flag word.
    pub fn end_of_range(&self) -> Option<FetchEndOfRange> {
        FetchEndOfRange::from_u64(self.flags())
    }

    /// Bit 0x40: the Object's Forwarding Preference is Datagram, so it has no
    /// Subgroup ID.
    ///
    /// Draft-16 Section 10.4.4.1 requires the publisher to set this bit for such
    /// an Object, says it SHOULD then zero the two least significant bits, and
    /// requires the subscriber to ignore them — so a Subgroup ID is not read
    /// even when those bits spell [`FetchSubgroupMode::Present`]. Ignoring them
    /// is a framing decision, not a cosmetic one: reading a Subgroup ID there
    /// would consume a varint that belongs to the next field.
    ///
    /// Never true for a [`FetchEndOfRange`] marker, whose value is not a flag
    /// word.
    pub fn is_datagram(&self) -> bool {
        self.end_of_range().is_none() && self.flags() & 0x40 != 0
    }

    /// The Table 5 reading of the two least significant bits.
    ///
    /// Answers [`FetchSubgroupMode::Zero`] for a [`FetchEndOfRange`] marker and
    /// for a Datagram-forwarded Object, neither of which has a Subgroup ID on
    /// the wire: Section 10.4.4.2 lists Subgroup ID among the fields an End of
    /// Range does not carry, and Section 10.4.4.1 says a Datagram Object has
    /// none at all.
    pub fn subgroup_mode(&self) -> FetchSubgroupMode {
        if self.end_of_range().is_some() || self.is_datagram() {
            return FetchSubgroupMode::Zero;
        }
        match self.flags() & 0x03 {
            0x00 => FetchSubgroupMode::Zero,
            0x01 => FetchSubgroupMode::SameAsPrior,
            0x02 => FetchSubgroupMode::PriorPlusOne,
            _ => FetchSubgroupMode::Present,
        }
    }

    /// Whether a Group ID field is on the wire (bit 0x08).
    ///
    /// Always true for a [`FetchEndOfRange`] marker: Section 10.4.4.2 says both
    /// the Group ID and the Object ID fields are present.
    pub fn has_group_id(&self) -> bool {
        self.end_of_range().is_some() || self.flags() & 0x08 != 0
    }

    /// Whether a Subgroup ID field is on the wire, which is
    /// [`FetchSubgroupMode::Present`] and nothing else.
    pub fn has_subgroup_id(&self) -> bool {
        matches!(self.subgroup_mode(), FetchSubgroupMode::Present)
    }

    /// Whether an Object ID field is on the wire (bit 0x04).
    ///
    /// Always true for a [`FetchEndOfRange`] marker, per Section 10.4.4.2.
    pub fn has_object_id(&self) -> bool {
        self.end_of_range().is_some() || self.flags() & 0x04 != 0
    }

    /// Whether a Publisher Priority byte is on the wire (bit 0x10).
    ///
    /// Never true for a [`FetchEndOfRange`] marker: Section 10.4.4.2 lists
    /// Priority among the fields it does not carry.
    pub fn has_priority(&self) -> bool {
        self.end_of_range().is_none() && self.flags() & 0x10 != 0
    }

    /// Whether an Extensions block is on the wire (bit 0x20).
    ///
    /// Never true for a [`FetchEndOfRange`] marker, per Section 10.4.4.2.
    pub fn has_extensions(&self) -> bool {
        self.end_of_range().is_none() && self.flags() & 0x20 != 0
    }

    /// Whether these flags read any field off the Object before this one.
    ///
    /// Draft-16 Section 10.4.4.1 closes the section on flags with: "If the first
    /// Object in the FETCH response uses a flag that references fields in the
    /// prior Object, the Subscriber MUST close the session with a
    /// PROTOCOL_VIOLATION." Four of the readings do that — an absent Group ID,
    /// Object ID or Priority each names the prior Object in Table 5 or Table 6,
    /// as do the two middle Subgroup ID modes.
    ///
    /// [`FetchSubgroupMode::Zero`] does not: it states a value outright. Nor
    /// does an absent Extensions block, which means the Object has none rather
    /// than the ones before it. A [`FetchEndOfRange`] marker references nothing
    /// either — its Group ID and Object ID are always present, and Section
    /// 10.4.4.2 gives it no Priority or Extensions to inherit.
    ///
    /// [`FetchObjectReader::resolve`] refuses the first Object of a stream when
    /// this is true of a field it would have to produce a value for. It is
    /// exposed separately because the draft's rule is wider than that: it also
    /// covers an absent Priority, for which Section 11.1.1.1 supplies a default
    /// that makes resolution possible anyway.
    pub fn references_prior_object(&self) -> bool {
        if self.end_of_range().is_some() {
            return false;
        }
        !self.has_group_id()
            || !self.has_object_id()
            || !self.has_priority()
            || matches!(
                self.subgroup_mode(),
                FetchSubgroupMode::SameAsPrior | FetchSubgroupMode::PriorPlusOne
            )
    }

    /// Encode the object's framing, refusing a struct that disagrees with its
    /// own Serialization Flags.
    ///
    /// The flags are the authority on which fields are on the wire, so a field
    /// that is `Some` while its flag is clear has nowhere to go, and one that is
    /// `None` while its flag is set leaves a hole the reader would fill from the
    /// bytes of the next field. Either way the result is a stream
    /// [`Self::decode`] cannot read back as what was handed in, so both are
    /// refused here.
    ///
    /// Errors with [`CodecError::InvalidField`] on any such disagreement, and on
    /// a Serialization Flags value at or above 128 that Table 4 does not assign,
    /// before a single byte is written — a refused object leaves `buf` untouched
    /// rather than half an object the next read would run into.
    ///
    /// The payload is not written: `payload_length` bytes of it belong on the
    /// stream immediately after these.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let flags = self.flags();
        if flags >= 128 && FetchEndOfRange::from_u64(flags).is_none() {
            return Err(CodecError::InvalidField);
        }
        if self.group_id.is_some() != self.has_group_id()
            || self.subgroup_id.is_some() != self.has_subgroup_id()
            || self.object_id.is_some() != self.has_object_id()
            || self.publisher_priority.is_some() != self.has_priority()
            || self.extensions.is_some() != self.has_extensions()
        {
            return Err(CodecError::InvalidField);
        }

        self.serialization_flags.encode(buf);
        if let Some(group_id) = self.group_id {
            group_id.encode(buf);
        }
        if let Some(subgroup_id) = self.subgroup_id {
            subgroup_id.encode(buf);
        }
        if let Some(object_id) = self.object_id {
            object_id.encode(buf);
        }
        if let Some(priority) = self.publisher_priority {
            buf.put_u8(priority);
        }
        if let Some(extensions) = &self.extensions {
            VarInt::from_usize(extensions.len()).encode(buf);
            buf.put_slice(extensions);
        }
        self.payload_length.encode(buf);
        Ok(())
    }

    /// Decode one object's framing, leaving `buf` positioned at its payload.
    ///
    /// Errors with [`CodecError::InvalidField`] when Serialization Flags is at
    /// or above 128 and is not one of the two values Table 4 assigns — draft-16
    /// Section 10.4.4 makes any other such value a PROTOCOL_VIOLATION, and there
    /// is no way to guess which fields follow it.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let serialization_flags = VarInt::decode(buf)?;
        let flags = serialization_flags.into_inner();
        if flags >= 128 && FetchEndOfRange::from_u64(flags).is_none() {
            return Err(CodecError::InvalidField);
        }
        // Presence is settled before any field is read, so the field order of
        // Figure 31 is followed exactly once: Group ID, Subgroup ID, Object ID,
        // Priority, Extensions, Object Payload Length.
        let probe = Self {
            serialization_flags,
            group_id: None,
            subgroup_id: None,
            object_id: None,
            publisher_priority: None,
            extensions: None,
            payload_length: VarInt::from_usize(0),
        };

        let group_id = if probe.has_group_id() { Some(VarInt::decode(buf)?) } else { None };
        let subgroup_id = if probe.has_subgroup_id() { Some(VarInt::decode(buf)?) } else { None };
        let object_id = if probe.has_object_id() { Some(VarInt::decode(buf)?) } else { None };
        let publisher_priority = if probe.has_priority() {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        } else {
            None
        };
        let extensions = if probe.has_extensions() {
            let ext_len = VarInt::decode(buf)?.into_inner() as usize;
            Some(crate::types::read_bytes(buf, ext_len)?)
        } else {
            None
        };
        let payload_length = VarInt::decode(buf)?;

        Ok(Self {
            serialization_flags,
            group_id,
            subgroup_id,
            object_id,
            publisher_priority,
            extensions,
            payload_length,
        })
    }
}

/// One fetch object's Location and priority, with every field the flags left
/// off the wire filled in from the Object before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchObjectLocation {
    /// Resolved absolute Group ID.
    pub group_id: u64,
    /// Resolved absolute Subgroup ID, and `None` for an Object whose Forwarding
    /// Preference is Datagram — draft-16 Section 10.2.1 omits the Subgroup ID
    /// for those, and Section 10.4.4.1 marks them with bit 0x40.
    pub subgroup_id: Option<u64>,
    /// Resolved absolute Object ID.
    pub object_id: u64,
    /// Publisher Priority, and `None` when no Object on the stream so far has
    /// stated one.
    ///
    /// That happens only after a [`FetchEndOfRange`] marker, which carries no
    /// Priority of its own and leaves the running value alone; any other first
    /// Object with no Priority is refused by [`FetchObjectReader::resolve`].
    /// Draft-16 Section 11.1.1.1 supplies the fallback for the gap — a
    /// subscription has Publisher Priority 128 when DEFAULT PUBLISHER PRIORITY
    /// is omitted — and it is left to the caller rather than substituted here,
    /// so that *the stream never said* stays distinguishable from "the stream
    /// said 128".
    pub publisher_priority: Option<u8>,
    /// The Table 4 marker this Object is, or `None` for an ordinary Object.
    ///
    /// When set, this Location is the far end of a span: Section 10.4.4.2 reads
    /// every Location between the previously serialized Object, if any, and
    /// this one — inclusive — as non-existent or unknown.
    pub end_of_range: Option<FetchEndOfRange>,
}

/// Stateful resolver for the Objects on one draft-16 fetch stream.
///
/// Draft-16 Section 10.4.4.1 lets an Object leave its Group ID, Subgroup ID,
/// Object ID or Priority off the wire and take the value from the Object before
/// it, so the fields of a fetch object are only meaningful in stream order.
/// This carries that running state; [`FetchObjectHeader`] carries only what the
/// bytes said.
///
/// Unlike a subgroup stream, nothing here is a delta: a field that is on the
/// wire replaces the running value outright, and a field that is absent either
/// repeats it or steps it by one, as Table 5 and Table 6 say.
#[derive(Debug, Clone, Default)]
pub struct FetchObjectReader {
    group_id: Option<u64>,
    subgroup_id: Option<u64>,
    object_id: Option<u64>,
    publisher_priority: Option<u8>,
}

impl FetchObjectReader {
    /// A reader positioned before the first Object of a fetch stream, with no
    /// prior Object to inherit from.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve one Object's Location against the Object before it, advancing
    /// the running state.
    ///
    /// Errors with [`CodecError::InvalidField`] when the first Object of the
    /// stream leaves out a Group ID or an Object ID, or names the prior
    /// Object's Subgroup ID: draft-16 Section 10.4.4.1 makes a first Object
    /// that "uses a flag that references fields in the prior Object" a
    /// PROTOCOL_VIOLATION, and for these three fields there is no value to
    /// produce even if it were not. An absent Priority is the same violation by
    /// the draft's letter and is reported by
    /// [`FetchObjectHeader::references_prior_object`], but it is resolvable —
    /// the Location simply carries no priority — so it is not refused here.
    ///
    /// Errors with [`CodecError::InvalidField`] when a Subgroup ID one greater
    /// than the prior Object's would not fit a varint.
    ///
    /// A [`FetchEndOfRange`] marker takes part in the running state like any
    /// other Object: Section 10.4.4.2 gives it a Location, and it is a
    /// "serialized Object" in the same section's words, so the Object after it
    /// inherits its Group ID and steps from its Object ID.
    pub fn resolve(
        &mut self,
        header: &FetchObjectHeader,
    ) -> Result<FetchObjectLocation, CodecError> {
        let group_id = match header.group_id {
            Some(v) => v.into_inner(),
            None => self.group_id.ok_or(CodecError::InvalidField)?,
        };

        let subgroup_id = if header.is_datagram() {
            None
        } else {
            match header.subgroup_mode() {
                FetchSubgroupMode::Zero => Some(0),
                FetchSubgroupMode::SameAsPrior => {
                    Some(self.subgroup_id.ok_or(CodecError::InvalidField)?)
                }
                FetchSubgroupMode::PriorPlusOne => {
                    let prior = self.subgroup_id.ok_or(CodecError::InvalidField)?;
                    let next = prior.checked_add(1).ok_or(CodecError::InvalidField)?;
                    VarInt::from_u64(next).map_err(|_| CodecError::InvalidField)?;
                    Some(next)
                }
                FetchSubgroupMode::Present => {
                    Some(header.subgroup_id.ok_or(CodecError::InvalidField)?.into_inner())
                }
            }
        };

        let object_id = match header.object_id {
            Some(v) => v.into_inner(),
            None => {
                let prior = self.object_id.ok_or(CodecError::InvalidField)?;
                let next = prior.checked_add(1).ok_or(CodecError::InvalidField)?;
                VarInt::from_u64(next).map_err(|_| CodecError::InvalidField)?;
                next
            }
        };

        // An Object that states no Priority leaves the running one alone, which
        // is what "Priority is the prior Object's Priority" asks for and also
        // what an End of Range marker — which has no Priority of its own —
        // needs.
        if let Some(priority) = header.publisher_priority {
            self.publisher_priority = Some(priority);
        }
        self.group_id = Some(group_id);
        // A Datagram-forwarded Object has no Subgroup ID at all, so it leaves no
        // "prior Object's Subgroup ID" behind: the next Object naming one is
        // refused rather than reaching past it to the Object before.
        self.subgroup_id = subgroup_id;
        self.object_id = Some(object_id);

        Ok(FetchObjectLocation {
            group_id,
            subgroup_id,
            object_id,
            publisher_priority: self.publisher_priority,
            end_of_range: header.end_of_range(),
        })
    }
}

/// Re-encodes resolved fetch Objects onto one FETCH stream.
///
/// The exact inverse of [`FetchObjectReader`], and it exists for one caller:
/// something that has read a stream and is writing a different stream from the
/// same Objects. Draft-16 Section 10.4.4.1 lets an Object leave out its Group
/// ID, Object ID, Subgroup ID and Priority and take the prior Object's, so
/// removing an Object changes what the Objects after it are read against: a
/// field the survivor left off has to appear, and a flag bit with it.
///
/// Every field draft-16 puts on the wire here is the absolute value rather than
/// a difference — the deltas arrive at draft-18. What is stateful is the
/// *omission*, and that is enough to make removal a re-encode.
///
/// # Why this is not a general encoder
///
/// Every Object it writes came off a stream, so the caller holds the Object's
/// own [`FetchObjectHeader`] beside its resolved
/// [`FetchObjectLocation`]. The header is used as the preference: wherever the
/// original shape still says the same thing against the new predecessor it is
/// kept, so a stream with nothing removed is reproduced byte for byte.
#[derive(Debug, Clone, Default)]
pub struct FetchObjectWriter {
    group_id: Option<u64>,
    subgroup_id: Option<u64>,
    object_id: Option<u64>,
    publisher_priority: Option<u8>,
}

impl FetchObjectWriter {
    /// A writer positioned before the first Object of a fetch stream, with no
    /// prior Object for anything to be written against.
    pub fn new() -> Self {
        Self::default()
    }

    /// The header that encodes `location` against everything written so far,
    /// starting from the shape `original` arrived in.
    ///
    /// Does not advance the writer — [`Self::write_object_header`] is the call
    /// that does both.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] for an Object with neither a Subgroup ID
    /// nor the Datagram bit, and where a value does not fit a variable-length
    /// integer.
    pub fn header_for(
        &self,
        original: &FetchObjectHeader,
        location: &FetchObjectLocation,
    ) -> Result<FetchObjectHeader, CodecError> {
        // A marker's Group ID and Object ID are on the wire by definition —
        // `has_group_id` and `has_object_id` are true for both marker values —
        // and it carries no Subgroup ID, Priority or Extensions.
        if original.end_of_range().is_some() {
            return Ok(FetchObjectHeader {
                serialization_flags: original.serialization_flags,
                group_id: Some(VarInt::from_u64(location.group_id)?),
                subgroup_id: None,
                object_id: Some(VarInt::from_u64(location.object_id)?),
                publisher_priority: None,
                extensions: None,
                payload_length: original.payload_length,
            });
        }

        let group_id = if !original.has_group_id() && self.group_id == Some(location.group_id) {
            None
        } else {
            Some(VarInt::from_u64(location.group_id)?)
        };
        let object_id = if !original.has_object_id()
            && self.object_id.and_then(|p| p.checked_add(1)) == Some(location.object_id)
        {
            None
        } else {
            Some(VarInt::from_u64(location.object_id)?)
        };
        let (subgroup_mode, subgroup_id) = self.subgroup_field(original, location)?;
        let publisher_priority = self.priority_field(original, location);

        let flags = original.flags();
        let mut new_flags = subgroup_mode;
        if flags & 0x40 != 0 {
            new_flags |= 0x40;
        }
        if group_id.is_some() {
            new_flags |= 0x08;
        }
        if object_id.is_some() {
            new_flags |= 0x04;
        }
        if publisher_priority.is_some() {
            new_flags |= 0x10;
        }
        if original.has_extensions() {
            new_flags |= 0x20;
        }

        Ok(FetchObjectHeader {
            serialization_flags: VarInt::from_u64(new_flags)?,
            group_id,
            subgroup_id,
            object_id,
            publisher_priority,
            extensions: original.extensions.clone(),
            payload_length: original.payload_length,
        })
    }

    /// The Subgroup ID mode bits and the explicit field, if one is needed.
    ///
    /// The Object's own mode is tried first, so a run that inherited its
    /// Subgroup ID keeps inheriting it and its bytes do not move.
    fn subgroup_field(
        &self,
        original: &FetchObjectHeader,
        location: &FetchObjectLocation,
    ) -> Result<(u64, Option<VarInt>), CodecError> {
        // With the Datagram bit set the two low bits say nothing and no field
        // is on the wire, so the Object's own bits are carried across.
        if original.is_datagram() {
            return Ok((original.flags() & 0x03, None));
        }

        let subgroup_id = location.subgroup_id.ok_or(CodecError::InvalidField)?;
        let inherits = self.subgroup_id == Some(subgroup_id);
        let successor = self.subgroup_id.is_some_and(|p| p.checked_add(1) == Some(subgroup_id));

        let kept = match original.subgroup_mode() {
            FetchSubgroupMode::Zero if subgroup_id == 0 => Some((0x00, None)),
            FetchSubgroupMode::SameAsPrior if inherits => Some((0x01, None)),
            FetchSubgroupMode::PriorPlusOne if successor => Some((0x02, None)),
            FetchSubgroupMode::Present => Some((0x03, Some(subgroup_id))),
            _ => None,
        };
        let (mode, explicit) = match kept {
            Some(pair) => pair,
            None if subgroup_id == 0 => (0x00, None),
            None if inherits => (0x01, None),
            None if successor => (0x02, None),
            None => (0x03, Some(subgroup_id)),
        };
        Ok((mode, explicit.map(VarInt::from_u64).transpose()?))
    }

    /// The Publisher Priority field, or `None` when the running one already
    /// says it.
    ///
    /// `location.publisher_priority` is the Priority in force rather than one
    /// this Object stated, so the comparison is against the Priority in force
    /// on the stream being written. Where the Object that stated it was the one
    /// removed, the two differ and this Object states it instead.
    fn priority_field(
        &self,
        original: &FetchObjectHeader,
        location: &FetchObjectLocation,
    ) -> Option<u8> {
        if original.has_priority() || self.publisher_priority != location.publisher_priority {
            return location.publisher_priority;
        }
        None
    }

    /// Encode `location` against everything written so far and advance.
    ///
    /// Writes the header only. The payload is `original.payload_length` bytes
    /// and is the caller's to copy, unchanged.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] for an Object with no encoding; the writer
    /// is left untouched when this happens.
    pub fn write_object_header(
        &mut self,
        original: &FetchObjectHeader,
        location: &FetchObjectLocation,
        out: &mut impl BufMut,
    ) -> Result<FetchObjectHeader, CodecError> {
        let header = self.header_for(original, location)?;
        header.encode(out)?;
        self.advance(&header, location);
        Ok(header)
    }

    /// Record what was written as the predecessor of whatever comes next.
    ///
    /// Mirrors [`FetchObjectReader::resolve`] exactly, including the two places
    /// draft-16 differs from the drafts after it: a Datagram-forwarded Object
    /// clears the running Subgroup ID rather than leaving it standing, and an
    /// Object that states no Priority leaves the running one alone.
    ///
    /// Public because a re-emitting caller has a second way of putting a frame
    /// on the wire: when the framing it arrived in still encodes the same
    /// meaning against the frame before it, its own bytes are forwarded
    /// untouched — no header is produced and nothing is copied. The writer
    /// still has to move, or the frame after it is encoded against a
    /// predecessor one frame stale. `written` is then the Object's own header, which is
    /// what was put on the wire.
    pub fn advance(&mut self, written: &FetchObjectHeader, location: &FetchObjectLocation) {
        if let Some(priority) = written.publisher_priority {
            self.publisher_priority = Some(priority);
        }
        self.group_id = Some(location.group_id);
        self.subgroup_id = location.subgroup_id;
        self.object_id = Some(location.object_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonically encoded subgroup stream vectors from
    /// `test-vectors/transport/draft16/codec/data-streams/subgroup.json`.
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
        // subgroup-nonempty-extensions
        "1101008000023c0104deadbeef",
        // subgroup-status-end-of-group
        "100105800004deadbeef000003",
        // subgroup-status-end-of-track
        "10010a800004deadbeef000004",
        // subgroup-extensions-two-objects-empty
        "11010080000004deadbeef000002cafe",
        // subgroup-extensions-two-objects-nonempty
        "1101008000023c0204deadbeef00023c0302cafe",
        // subgroup-extensions-status-object
        "1101008000023c010003",
        // subgroup-end-of-group
        "180105800004deadbeef",
        // subgroup-id-first-object
        "120103800504deadbeef",
    ];

    fn vi(v: u64) -> VarInt {
        VarInt::from_u64(v).unwrap()
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
    fn two_objects_with_extensions_have_distinct_ids() {
        // Vector `subgroup-extensions-two-objects-empty`: two objects, each
        // carrying an empty extensions block and a delta of 0. The delta is
        // biased by one whether or not the extensions bit is set, so the IDs
        // are 0 and 1 — not 0 and 0.
        let bytes = hex("11010080000004deadbeef000002cafe");
        let (header, objects) = decode_all(&bytes);
        assert!(header.has_extensions());
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

    // ── Extension blocks ──────────────────────────────

    #[test]
    fn extensions_blob_excludes_its_length_prefix() {
        // Vector `subgroup-extensions-two-objects-nonempty`: each
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
    fn status_object_carries_its_extensions_block() {
        let (_, objects) = decode_all(&hex("1101008000023c010003"));
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].extension_headers, hex("3c01"));
        assert_eq!(objects[0].payload_length.into_inner(), 0);
        assert_eq!(objects[0].object_status.map(ObjectStatus::as_u64), Some(3));
        assert!(objects[0].payload.is_empty());
    }

    // ── Object status ───────────────────────────────────────

    /// A subgroup header with neither extensions nor an explicit subgroup ID,
    /// so an object on this stream is just `delta, payload_length, [status]`.
    fn plain_header() -> SubgroupHeader {
        SubgroupHeader::decode(&mut &hex("100100800004deadbeef")[..]).unwrap()
    }

    /// A status object on a [`plain_header`] stream: object 0, empty payload,
    /// `code` as the status. Every code used here is one wire byte.
    fn subgroup_status_body(code: u64) -> Vec<u8> {
        let mut buf = vec![0x00, 0x00];
        VarInt::from_u64(code).unwrap().encode(&mut buf);
        buf
    }

    fn status_object(status: Option<ObjectStatus>) -> SubgroupObject {
        SubgroupObject {
            object_id: vi(0),
            extension_headers: vec![],
            payload_length: vi(0),
            object_status: status,
            payload: vec![],
        }
    }

    /// A status datagram carrying `code`. Type 0x20 sets the status flag and
    /// leaves the object-id (0x04), default-priority (0x08) and extensions
    /// (0x01) flags clear, so the layout is `type, track_alias, group_id,
    /// object_id, priority, status`.
    fn datagram_status_bytes(code: u64) -> Vec<u8> {
        let mut buf = vec![0x20, 0x01, 0x02, 0x03, 0x80];
        VarInt::from_u64(code).unwrap().encode(&mut buf);
        buf
    }

    fn status_datagram(status: Option<ObjectStatus>) -> DatagramHeader {
        DatagramHeader {
            datagram_type: 0x20,
            track_alias: vi(1),
            group_id: vi(2),
            object_id: vi(3),
            publisher_priority: Some(0x80),
            extension_headers: vec![],
            object_status: status,
        }
    }

    /// Every status the type can hold reaches the wire as its own code and
    /// comes back unchanged, through both subgroup readers and the datagram.
    ///
    /// Observed by making `write_object` encode `ObjectStatus::Normal` instead
    /// of the object's own status, which fails this with:
    ///
    /// ```text
    /// assertion `left == right` failed: EndOfGroup on the subgroup wire
    ///   left: [0, 0, 0]
    ///  right: [0, 0, 3]
    /// ```
    #[test]
    fn assigned_statuses_round_trip() {
        let header = plain_header();
        for &status in ObjectStatus::ALL {
            let mut bytes = Vec::new();
            SubgroupObjectReader::new(&header)
                .write_object(&status_object(Some(status)), &mut bytes)
                .unwrap();
            assert_eq!(
                bytes,
                subgroup_status_body(status.as_u64()),
                "{status:?} on the subgroup wire"
            );

            let decoded = SubgroupObjectReader::new(&header)
                .read_object(&mut &bytes[..])
                .unwrap_or_else(|e| panic!("{status:?} was written and then refused: {e:?}"));
            assert_eq!(decoded.object_status, Some(status), "{status:?} through read_object");

            let meta = SubgroupObjectReader::new(&header)
                .read_object_meta(&mut &bytes[..])
                .unwrap_or_else(|e| panic!("{status:?} was written and then refused: {e:?}"));
            assert_eq!(meta.status, Some(status.as_u64()), "{status:?} through read_object_meta");

            let datagram = status_datagram(Some(status));
            let mut bytes = Vec::new();
            datagram.encode(&mut bytes);
            assert_eq!(
                bytes,
                datagram_status_bytes(status.as_u64()),
                "{status:?} on the datagram wire"
            );
            let decoded = DatagramHeader::decode(&mut &bytes[..]).unwrap_or_else(|e| {
                panic!("{status:?} datagram was written and then refused: {e:?}")
            });
            assert_eq!(decoded, datagram, "{status:?} datagram round trip");
        }
    }

    /// A datagram whose type byte sets the status flag always carries a status
    /// field, because the flag is what puts the field on the wire — an unset
    /// `object_status` writes Normal rather than nothing.
    ///
    /// Observed by putting back the `if let Some(s) = &self.object_status`
    /// with no `else`, which emits a datagram that stops before its status
    /// field and fails this with:
    ///
    /// ```text
    /// assertion `left == right` failed
    ///   left: [32, 1, 2, 3, 128]
    ///  right: [32, 1, 2, 3, 128, 0]
    /// ```
    ///
    /// and, with the byte comparison removed, fails the decode of its own
    /// output with `own output refused: VarInt(UnexpectedEnd)`.
    #[test]
    fn a_status_datagram_without_a_status_encodes_normal() {
        let mut bytes = Vec::new();
        status_datagram(None).encode(&mut bytes);
        assert_eq!(bytes, datagram_status_bytes(ObjectStatus::Normal.as_u64()));
        let decoded = DatagramHeader::decode(&mut &bytes[..])
            .unwrap_or_else(|e| panic!("own output refused: {e:?}"));
        assert_eq!(decoded.object_status, Some(ObjectStatus::Normal));
    }

    /// The codes this draft's decoders accept are exactly the codes its
    /// encoders can emit.
    ///
    /// The sweep covers `0x00..=0x3f`, the whole one-byte varint range, so it
    /// contains every code draft-16 assigns, the gap inside that range (0x2)
    /// and the code draft-16 dropped (0x1, Object Does Not Exist). The
    /// expected set is read from [`ObjectStatus::ALL`] rather than written out
    /// here, so reassigning a code moves both halves of the test at once.
    ///
    /// Observed by teaching `ObjectStatus::from_u64` to answer `Some` for 0x1
    /// again — the code draft-15 assigned to Object Does Not Exist and
    /// draft-16 dropped, mapped onto a surviving variant since draft-16 has no
    /// variant of its own for it — which fails this with:
    ///
    /// ```text
    /// assertion `left == right` failed: subgroup read_object on status 0x1: Ok(SubgroupObject { object_id: VarInt(0), extension_headers: [], payload_length: VarInt(0), object_status: Some(Normal), payload: [] })
    ///   left: true
    ///  right: false
    /// ```
    #[test]
    fn the_wire_accepts_exactly_what_the_type_can_hold() {
        let header = plain_header();
        for code in 0x00u64..=0x3f {
            let assigned = ObjectStatus::ALL.iter().any(|s| s.as_u64() == code);
            let body = subgroup_status_body(code);

            let read = SubgroupObjectReader::new(&header).read_object(&mut &body[..]);
            assert_eq!(
                read.is_ok(),
                assigned,
                "subgroup read_object on status {code:#x}: {read:?}"
            );

            let meta = SubgroupObjectReader::new(&header).read_object_meta(&mut &body[..]);
            assert_eq!(
                meta.is_ok(),
                assigned,
                "subgroup read_object_meta on status {code:#x}: {meta:?}"
            );

            let datagram = DatagramHeader::decode(&mut &datagram_status_bytes(code)[..]);
            assert_eq!(
                datagram.is_ok(),
                assigned,
                "status datagram on status {code:#x}: {datagram:?}"
            );

            // The other direction: an accepted code is one the encoders can
            // reach, and they reach it with exactly these bytes.
            if assigned {
                let status = ObjectStatus::from_u64(code).unwrap();
                let mut bytes = Vec::new();
                SubgroupObjectReader::new(&header)
                    .write_object(&status_object(Some(status)), &mut bytes)
                    .unwrap();
                assert_eq!(bytes, body, "write_object on status {code:#x}");
                let mut bytes = Vec::new();
                status_datagram(Some(status)).encode(&mut bytes);
                assert_eq!(
                    bytes,
                    datagram_status_bytes(code),
                    "datagram encode on status {code:#x}"
                );
            }
        }
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
}

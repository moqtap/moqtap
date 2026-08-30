//! Draft-15 data stream header encoding and decoding.
//!
//! Draft-15 data streams differ significantly from draft-14:
//! - Subgroup stream types encode flags in the type byte. Section 10.4.2
//!   Table 6 assigns twenty-four: `0x10`-`0x15`, `0x18`-`0x1D`, `0x30`-`0x35`
//!   and `0x38`-`0x3D`.
//! - Priority is absent when `type & 0x20`, and the object then inherits the
//!   priority the subscription established
//! - `type & 0x06` decides how the Subgroup ID is carried: it is zero, it is
//!   the first object's ID, or it is a field on the wire. Table 6 states that
//!   as two columns — Subgroup ID Field Present, and Subgroup ID Value — not
//!   as a mode field, and the fourth combination is simply not a row in it
//! - `type & 0x08` marks a stream whose last object ends its group
//! - Extensions flag (`type & 0x01`) affects per-object parsing
//! - Fetch objects use serialization_flags for delta encoding
//! - Object IDs in subgroups use delta encoding (first=absolute, subsequent=delta+1)

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

/// Turn a wire Object Status code into the status draft-15 gives it, refusing
/// any code the draft does not assign.
///
/// Draft-15 Section 10.2.1.1 lists the codes an object may carry and says any
/// other value SHOULD be treated as a protocol error and the session
/// terminated with a PROTOCOL_VIOLATION. Every place this module reads a
/// status runs the wire code through here.
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

/// Refuse an object that would be written with extension headers beside a
/// status other than Normal.
///
/// Draft-15 Section 10.2.1.2: "Any Object with status Normal can have extension
/// headers. If an endpoint receives extension headers on Objects with status
/// that is not Normal, it MUST close the session with a PROTOCOL_VIOLATION."
///
/// Wider than the rule drafts 11 through 14 carry. There, at
/// draft-14 Section 10.2.1.2, the sentence read "Any Object may have extension
/// headers except those with Object Status 'Object Does Not Exist'", which left
/// extensions beside End of Group and End of Track legal; draft-15 is where the
/// single exception became the general case. Using the earlier wording here
/// would let an End of Group object carry metadata draft-15 says to close the
/// session over.
///
/// **Called from [`DatagramHeader::encode_checked`] and nowhere else, and
/// deliberately so.** A frame carrying extensions beside a non-Normal status is
/// well formed — every length is honest and every field parses — so a decoder
/// can hand it back intact, and a tool that reproduces a capture has to.
/// Refusing it on decode would make a captured violation unreadable, which
/// loses the one artifact anybody debugging it needs.
///
/// The same argument bars it from a carrier's only writer.
/// [`SubgroupObjectReader::write_object`] and
/// [`FetchObjectReader::write_object_header`] are the sole way to write their
/// objects, so a refusal there would leave a captured violation impossible to
/// re-emit; the corpus ships exactly such a subgroup frame. A datagram is the
/// one carrier with two encoders, so `encode_checked` can refuse while
/// [`DatagramHeader::encode`] still reproduces bytes verbatim. That is the
/// whole of the rule: opt-in strictness where an unchecked path exists, and a
/// predicate — [`SubgroupObject::extensions_permitted`],
/// [`SubgroupObjectMeta::extensions_permitted`],
/// [`DatagramHeader::extensions_permitted`],
/// [`FetchObjectHeader::extensions_permitted`] — everywhere else.
///
/// That is why drafts 11 through 14 look different and should stay different:
/// they state only the narrow Object Does Not Exist form, they apply it on both
/// sides, and no vector exercises it. Drafts 15 through 19 state the broad form
/// and enforce it on encode alone. The split is intentional, not an
/// inconsistency to harmonise away.
///
/// `status` is the code the object resolves to, not the field as it appears on
/// the wire. An object whose framing omits the status field has status Normal —
/// on a subgroup or fetch stream because its payload length is non-zero, on a
/// datagram because its type byte leaves the status bit clear — and such an
/// object may carry extensions. Passing `None` says exactly that.
fn check_extensions_against_status_on_encode(
    status: Option<u64>,
    extension_headers_len: u64,
) -> Result<(), CodecError> {
    if extension_headers_len != 0
        && matches!(status, Some(code) if code != ObjectStatus::Normal.as_u64())
    {
        return Err(CodecError::InvalidField);
    }
    Ok(())
}

// ── Payload permission ─────────────────────────────────────

/// Whether an object carrying a given status may hold a non-empty payload.
///
/// Draft-15 Section 10.2.1.1 states the rule in one sentence — "Any object with
/// a status code other than zero MUST have an empty payload" — and Section
/// 10.2.1 says the same from the other side, listing the Object Payload as
/// "Only present when 'Object Status' is Normal (0x0)". On this draft the
/// answer therefore falls out of the code being zero or not, and every status
/// but [`ObjectStatus::Normal`] forbids a payload.
///
/// It is worth a type all the same, because that arithmetic is not something a
/// consumer can safely perform on a raw wire code. A code draft-15 does not
/// assign is not *non-zero, and therefore forbidden*: it is a code with no
/// meaning at all, and the draft's answer to it is to terminate the session,
/// not to infer a payload rule. Handing back a `PayloadPermission` keeps the
/// two apart, and lets a caller ask the question without restating the rule —
/// or, worse, restating it slightly differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadPermission {
    /// The status permits a payload but does not require one: a zero-length
    /// object with such a status is well formed, and draft-15's encodings have
    /// a way to spell it.
    Permitted,
    /// An object with such a status has an empty payload, and one carrying
    /// bytes is malformed.
    Forbidden,
}

impl PayloadPermission {
    /// The permission draft-15 gives objects carrying `status`.
    ///
    /// Written as a match over every assigned status rather than as a test for
    /// zero, so that a status added to [`ObjectStatus`] later cannot quietly
    /// inherit *not Normal, therefore forbidden* — it stops the crate compiling
    /// until its own answer is written down. Drafts after 15 moved this rule
    /// into a column of the Object Status registry, where a future status may
    /// well permit a payload; the shape here does not have to change when a
    /// caller crosses that boundary.
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

// ── Subgroup streams ───────────────────────────────────────

/// Subgroup stream header for draft-15.
///
/// Draft-15 Section 10.4.2 Table 6 assigns twenty-four stream types, built from
/// a base of `0x10` or `0x30` and three independent fields:
/// - `& 0x01`: extensions present on objects
/// - `& 0x06`: how the Subgroup ID is carried — `0x00` it is zero, `0x02` it
///   is the Object ID of the first object on the stream and is not
///   transmitted, `0x04` it is a field on the wire. `0x06` is not a row
/// - `& 0x08`: the last object on the stream ends its group
/// - `& 0x20`: no publisher priority; the object inherits the one the
///   subscription established
///
/// **These two bits are read together, not as two independent flags**, and the
/// table is what settles it: it gives them as a pair of columns, Subgroup ID
/// Field Present and Subgroup ID Value, and no row carries both a present
/// field and a value taken from the first object. Reading `0x02` as an
/// end-of-group marker — which is what this did — answers the wrong question
/// in both directions: a real end-of-group stream (`0x18`-`0x1D`,
/// `0x38`-`0x3D`) reports `false`, and a first-object stream (`0x12`, `0x13`)
/// reports `true`. Neither is a framing error, so nothing downstream notices.
///
/// Draft-16 later folds the same three choices into a named SUBGROUP_ID_MODE
/// field with a fourth, reserved value. Draft-15 has no such name and no such
/// value: `0x16`, `0x17`, `0x1E`, `0x1F`, `0x36`, `0x37`, `0x3E` and `0x3F`
/// are absent from Table 6 rather than reserved by it, and the word does not
/// appear here in that sense at all. The two drafts agree on every byte and
/// differ only in how they say why, so borrowing the later vocabulary reads
/// as though draft-15 states something it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupHeader {
    pub header_type: u8,
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub subgroup_id: VarInt,
    pub publisher_priority: Option<u8>,
}

/// Whether draft-15 Section 10.4.2 Table 6 assigns this subgroup stream type.
///
/// Twenty-four values are assigned, counted off the table itself: `0x10`-`0x15`
/// and `0x18`-`0x1D`, then `0x30`-`0x35` and `0x38`-`0x3D`. A type is valid
/// when its base is `0x10` or `0x30` and its `0x06` bits name one of the three
/// ways the table carries a Subgroup ID. That leaves `0x16`, `0x17`, `0x1E`,
/// `0x1F`, `0x36`, `0x37`, `0x3E` and `0x3F` with no row.
///
/// They are **unassigned, not reserved.** Draft-16 reserves the same eight by
/// name; draft-15 reaches them by omission and says nothing about them at all.
/// The test is the same either way, which is why the distinction is only worth
/// a sentence — but the sentence keeps the next reader from carrying draft-16's
/// vocabulary back into a draft that does not use it.
///
/// Section 10 requires closing the session on a stream type the draft does not
/// define, so accepting one and inventing a framing for it — the decoder read a
/// Subgroup ID field for these, because `0x04` happens to be set — is not a
/// harmless leniency.
fn subgroup_type_is_assigned(ty: u64) -> bool {
    let Ok(ty) = u8::try_from(ty) else {
        return false;
    };
    // The `0x20` bit is the one difference between the two assigned bases, and
    // masking with `0xD0` rather than `0xF0` drops it — so `0x30` through `0x3F`
    // fold onto `0x10` and one comparison covers both. Every other high nibble
    // survives the mask as something other than `0x10` and is refused: `0x20`
    // folds to `0x00`, `0x50` and `0x70` to `0x50`, and so on up.
    (ty & 0xD0) == 0x10 && (ty & 0x06) != 0x06
}

impl SubgroupHeader {
    pub fn has_extensions(&self) -> bool {
        self.header_type & 0x01 != 0
    }

    /// When set, the Subgroup ID is the Object ID of the first object on the
    /// stream and is not transmitted. The `0x02` row of the `0x06` bits.
    pub fn subgroup_id_from_first_object(&self) -> bool {
        self.header_type & 0x06 == 0x02
    }

    pub fn has_explicit_subgroup_id(&self) -> bool {
        self.header_type & 0x06 == 0x04
    }

    pub fn has_end_of_group(&self) -> bool {
        self.header_type & 0x08 != 0
    }

    pub fn has_priority(&self) -> bool {
        self.header_type & 0x20 == 0
    }

    /// Encode the header, writing whichever fields the type byte announces.
    ///
    /// Field presence follows `header_type`, because that is what the peer
    /// reads. A `publisher_priority` of `None` under a type whose `0x20` bit is
    /// clear writes a zero rather than dropping the byte: omitting it would
    /// leave the peer reading the first object's Object ID Delta as a priority
    /// and desync the whole stream. Use [`encode_checked`](Self::encode_checked)
    /// to be told about the disagreement instead of having it papered over.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.header_type as usize).encode(buf);
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        if self.has_explicit_subgroup_id() {
            self.subgroup_id.encode(buf);
        }
        if self.has_priority() {
            buf.put_u8(self.publisher_priority.unwrap_or(0));
        }
    }

    /// Encode, refusing a header whose fields disagree with its own type byte.
    ///
    /// [`encode`](Self::encode) is driven by `header_type` and
    /// [`decode`](Self::decode) reads the same byte, so the two agree on the
    /// wire whatever the struct holds —
    /// but a caller that sets `publisher_priority` beside a type whose `0x20`
    /// bit is set, or leaves it `None` beside one whose bit is clear, has built
    /// a header that does not mean what it says. The fetch object writer
    /// already refuses that shape; this is the same check one layer up.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        if self.has_priority() != self.publisher_priority.is_some() {
            return Err(CodecError::InvalidField);
        }
        if !subgroup_type_is_assigned(self.header_type as u64) {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        // Compared as the full varint rather than truncated to `u8`: a type of
        // `0x110` narrows to `0x10` and would be accepted as a plain subgroup
        // header, so a stream this draft does not define would be parsed as one
        // it does instead of closing the session.
        let type_value = VarInt::decode(buf)?.into_inner();
        if !subgroup_type_is_assigned(type_value) {
            return Err(stream_type_error(type_value));
        }
        let header_type = type_value as u8;
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        // `0x04` alone carries the Subgroup ID on the wire. `0x02` takes it
        // from the first object, which the stream reader resolves, and `0x00`
        // defines it as zero.
        let subgroup_id = if type_value as u8 & 0x06 == 0x04 {
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

// ── Subgroup objects (stateful) ─────────────────────────────

/// One object within a draft-15 subgroup stream with its Object ID
/// already resolved from the delta encoding.
///
/// Draft-15 object framing requires context from the enclosing
/// [`SubgroupHeader`] (specifically, whether extension headers are
/// present and the running delta state), so decoding/encoding uses a
/// stateful [`SubgroupObjectReader`] rather than a standalone method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupObject {
    /// Resolved absolute Object ID.
    pub object_id: VarInt,
    /// Raw extension-header bytes, excluding the byte-length prefix that
    /// precedes them on the wire. Empty when the stream header does not
    /// set the extensions-present bit, or when the block is present but
    /// zero-length. Opaque: [`SubgroupObjectReader::write_object`] re-emits
    /// the prefix and these bytes verbatim.
    pub extension_headers: Vec<u8>,
    /// Payload length as encoded on the wire. Zero when the object is
    /// a status-only object.
    pub payload_length: VarInt,
    /// Object status; `Some` when `payload_length == 0`.
    ///
    /// The wire field is a varint, so it can carry any value up to 2^62-1;
    /// draft-15 Section 10.2.1.1 assigns four of them and says a peer SHOULD
    /// treat the rest as a protocol error. This field is typed to the assigned
    /// set, so it refuses to hold the codes the draft leaves unassigned —
    /// 0x2, and everything from 0x5 up. That makes the refusal a property of
    /// the struct rather than of any one code path: an encoder cannot be
    /// handed a status the draft does not define, and does not have to check.
    ///
    /// `None` on a zero-length object means the same thing as
    /// [`ObjectStatus::Normal`] and encodes as it; the wire field is not
    /// optional once `payload_length` is zero.
    pub object_status: Option<ObjectStatus>,
    /// Payload bytes; empty when `object_status` is `Some`.
    pub payload: Vec<u8>,
}

impl SubgroupObject {
    /// The status this object resolves to.
    ///
    /// The wire carries a status field only on a zero-length object, so an
    /// object holding bytes is [`ObjectStatus::Normal`] whatever
    /// [`Self::object_status`] says — draft-15 Section 10.2.1.1: "This status is
    /// implicit for any non-zero length object."
    pub fn status(&self) -> ObjectStatus {
        if self.payload_length.into_inner() == 0 {
            self.object_status.unwrap_or(ObjectStatus::Normal)
        } else {
            ObjectStatus::Normal
        }
    }

    /// Whether this object's status is allowed to carry the extension headers
    /// it has.
    ///
    /// Draft-15 Section 10.2.1.2: "Any Object with status Normal can have
    /// extension headers. If an endpoint receives extension headers on Objects
    /// with status that is not Normal, it MUST close the session with a
    /// PROTOCOL_VIOLATION."
    ///
    /// So this is `false` for exactly one shape: a non-empty extension block on
    /// an object whose status is not [`ObjectStatus::Normal`]. An object with no
    /// extensions is fine at any status, and an object at Normal may carry any
    /// extensions.
    ///
    /// Neither [`SubgroupObjectReader::read_object`] nor
    /// [`SubgroupObjectReader::write_object`] applies this itself, which is a
    /// deliberate contrast with the payload rule beside it. A status next to a
    /// payload has no encoding — the two share a position on the wire — so the
    /// writer refuses it as unrepresentable. Extensions next to a status encode
    /// fine; the frame is well formed and merely non-conforming, and a codec
    /// that could not read or write it could not reproduce a capture containing
    /// one. The corpus ships exactly such a frame. The rule addresses an
    /// endpoint receiving the Object, so the endpoint is where it is enforced,
    /// and this is what it asks.
    pub fn extensions_permitted(&self) -> bool {
        self.extension_headers.is_empty() || self.status() == ObjectStatus::Normal
    }
}

/// The framing of one draft-15 subgroup object, without its payload.
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
    /// still one draft-15 assigns — `read_object_meta` refuses the others.
    pub status: Option<u64>,
    /// Total bytes this object occupies on the wire, prefix fields included.
    pub wire_len: u64,
}

impl SubgroupObjectMeta {
    /// Whether this object is permitted a non-empty payload, or `None` when
    /// [`Self::status`] holds a code draft-15 does not assign.
    ///
    /// [`Self::status`] is a raw wire code, so the rule of draft-15 Section
    /// 10.2.1.1 — "Any object with a status code other than zero MUST have an
    /// empty payload" — cannot be read off it without first deciding what the
    /// code means. This does that decision once: a consumer asking whether an
    /// object may carry bytes gets an answer instead of a number and a rule to
    /// apply to it.
    ///
    /// An absent status answers [`PayloadPermission::Permitted`] rather than
    /// `None`. A meta has no status only when its payload length is non-zero,
    /// and Section 10.2.1.1 says of Normal that "This status is implicit for
    /// any non-zero length object" — the object has a status, the encoding just
    /// does not spell it.
    ///
    /// `None` means the code is one the draft leaves unassigned, and so one it
    /// gives no payload rule for. That is not reachable through
    /// [`SubgroupObjectReader::read_object_meta`], which refuses such a code
    /// before it can reach the field, but the fields here are public and a meta
    /// assembled by hand — by a relay carrying a status across from a draft that
    /// numbers them differently, say — can hold anything a varint can. The
    /// answer there is that draft-15 has none, not that the payload is
    /// forbidden.
    pub fn payload_permission(&self) -> Option<PayloadPermission> {
        match self.status {
            None => Some(PayloadPermission::Permitted),
            Some(code) => ObjectStatus::from_u64(code).map(PayloadPermission::for_status),
        }
    }

    /// Whether this object's status is allowed to carry the extension block it
    /// declares.
    ///
    /// The same rule [`SubgroupObject::extensions_permitted`] answers, from the
    /// declared length rather than from the bytes. A relay that forwards an
    /// object verbatim reads it through
    /// [`SubgroupObjectReader::read_object_meta`] and never copies the block, so
    /// asking this must not require having it — draft-15 Section 10.2.1.2 turns
    /// on whether the block is empty, and the length says that on its own.
    ///
    /// A status this draft does not assign answers `None` rather than `false`,
    /// for the reason [`Self::payload_permission`] gives: the draft states no
    /// rule for a code it does not define, and a meta assembled by hand can
    /// hold one. `read_object_meta` refuses such a code before it reaches the
    /// field.
    ///
    /// An absent status answers from Normal. A meta has no status only when its
    /// payload length is non-zero, and such an object is Normal by Section
    /// 10.2.1.1, so its extensions are permitted.
    pub fn extensions_permitted(&self) -> Option<bool> {
        if self.extension_headers_len == 0 {
            return Some(true);
        }
        match self.status {
            None => Some(true),
            Some(code) => ObjectStatus::from_u64(code).map(|s| s == ObjectStatus::Normal),
        }
    }
}

/// Stateful reader/writer for draft-15 subgroup objects.
///
/// Carries the running delta state for object IDs and remembers whether
/// extension headers are present on this stream.
#[derive(Debug, Clone)]
pub struct SubgroupObjectReader {
    extensions_present: bool,
    prev_object_id: Option<u64>,
}

impl SubgroupObjectReader {
    /// Build a reader seeded from the enclosing subgroup header.
    pub fn new(header: &SubgroupHeader) -> Self {
        Self { extensions_present: header.has_extensions(), prev_object_id: None }
    }

    /// Decode the next object from `buf`.
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

        let extension_headers = if self.extensions_present {
            // Draft-15+: extensions are a byte-length-prefixed opaque
            // blob. We copy the blob verbatim; callers that want
            // structured extensions can parse the returned bytes.
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
    /// [`ObjectStatus::Normal`]. The code written is always one draft-15
    /// assigns, because the field cannot hold any other, so the bytes this
    /// produces are always bytes [`SubgroupObjectReader::read_object`] accepts.
    ///
    /// Errors with [`CodecError::InvalidField`] when `payload_length` is not
    /// exactly `payload.len()`. The declared length is written ahead of the
    /// payload, so a mismatch is a frame [`Self::read_object`] cannot parse
    /// and one no caller could fix by appending bytes.
    ///
    /// Does NOT refuse extension headers beside a status other than Normal,
    /// though draft-15 Section 10.2.1.2 forbids them. Such a frame is well
    /// formed and merely non-conforming, this is the only writer a subgroup
    /// object has, and the corpus ships one — so refusing here would leave a
    /// captured violation impossible to reproduce.
    /// [`SubgroupObject::extensions_permitted`] reports it instead.
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

        // Extension headers beside a non-Normal status are NOT refused here,
        // though draft-15 Section 10.2.1.2 forbids them. The two rules around a
        // status differ in kind. A payload beside a status has no encoding at
        // all — the status field and the payload occupy the same position, so
        // no sequence of bytes states both — which is why the declared-length
        // check above refuses it as unrepresentable. Extensions beside a status
        // encode perfectly well and read back byte for byte; the frame is well
        // formed and non-conforming, which is a judgement about what a peer may
        // send rather than about what the bytes mean.
        //
        // This is the only writer for a subgroup object, so refusing here would
        // leave no way to reproduce a capture containing such a frame — and the
        // corpus ships one. [`SubgroupObject::extensions_permitted`] reports the
        // violation instead, and the endpoint acts on it.
        // [`DatagramHeader::encode_checked`] does refuse it, because a plain
        // [`DatagramHeader::encode`] stands beside it for verbatim reproduction.

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

// ── Datagram headers ───────────────────────────────────────

/// Whether draft-15 Section 10.3.1 Table 5 assigns this datagram type.
///
/// Twenty-four values are assigned: `0x00`-`0x0F`, and `0x20`, `0x21`, `0x24`,
/// `0x25`, `0x28`, `0x29`, `0x2C`, `0x2D`. Two rules generate that set. A type
/// may only use the bits the draft defines — `0x01` extensions, `0x02` end of
/// group, `0x04` no object ID, `0x08` default priority, `0x20` status — so any
/// other bit makes it undefined. And a status datagram cannot also mark the end
/// of a group, which rules out every type setting `0x20` and `0x02` together.
///
/// Section 10 requires closing the session on a datagram type the draft does
/// not define. Accepting one means inferring field presence from bits that
/// carry no meaning, which is how an undefined type gets parsed as a
/// well-formed object.
///
/// Note that Section 10 Table 4 lists only ten datagram types and describes
/// them as the whole set. That table is draft-14 text left behind: Table 5 in
/// Section 10.3.1 is the normative field-presence table, it lists twenty-four,
/// and draft-16 follows it.
fn datagram_type_is_assigned(ty: u64) -> bool {
    let Ok(ty) = u8::try_from(ty) else {
        return false;
    };
    ty & 0xD0 == 0 && ty & 0x22 != 0x22
}

/// Datagram header for draft-15.
///
/// The `datagram_type` byte encodes flags:
/// - `0x02`: end-of-group
/// - `0x04`: no object_id (object_id = 0 implied)
/// - `0x20`: status datagram (carries object_status instead of payload)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramHeader {
    /// Raw datagram-type byte encoding flags + kind.
    pub datagram_type: u8,
    /// Track alias identifying the track.
    pub track_alias: VarInt,
    /// Group ID for the contained object.
    pub group_id: VarInt,
    /// Object ID (zero when the `no-object-id` flag is set).
    pub object_id: VarInt,
    /// Publisher priority, present only when the type byte leaves the
    /// default-priority bit (`0x08`) clear.
    ///
    /// `None` means the object inherits the priority the control message that
    /// established the subscription specified — draft-15 Section 10.3.1. This
    /// is optional here and not on draft-14 because draft-15 is the draft that
    /// made it so.
    pub publisher_priority: Option<u8>,
    /// Opaque extension-headers blob (only when the `0x01` flag is set).
    pub extension_headers: Vec<u8>,
    /// Object status (only when the `0x20` status flag is set).
    ///
    /// The wire field is a varint and can carry any value up to 2^62-1;
    /// draft-15 Section 10.2.1.1 assigns four of them and says a peer SHOULD
    /// treat the rest as a protocol error. This field is typed to the assigned
    /// set, so it cannot hold 0x2 or anything from 0x5 up — [`Self::encode`]
    /// therefore needs no check and cannot emit a datagram that
    /// [`Self::decode`] would reject.
    ///
    /// `None` while the status flag is set encodes as
    /// [`ObjectStatus::Normal`]: once the flag is set the field is present on
    /// the wire, so there is nothing for `None` to mean but the default.
    pub object_status: Option<ObjectStatus>,
}

impl DatagramHeader {
    /// Whether the datagram carries an explicit object_id.
    pub fn has_object_id(&self) -> bool {
        self.datagram_type & 0x04 == 0
    }

    /// Whether this datagram marks the end of its group.
    pub fn is_end_of_group(&self) -> bool {
        self.datagram_type & 0x02 != 0
    }

    /// Whether this datagram carries an object_status instead of payload.
    pub fn is_status(&self) -> bool {
        self.datagram_type & 0x20 != 0
    }

    /// Whether this datagram carries extension headers.
    pub fn has_extensions(&self) -> bool {
        self.datagram_type & 0x01 != 0
    }

    /// Whether the publisher priority is omitted and inherited.
    ///
    /// Draft-15 Section 10.3.1: with Priority Present set to No the field is
    /// absent and "this Object inherits the Publisher Priority specified in the
    /// control message that established the subscription". New in draft-15;
    /// draft-14 always carries the byte.
    pub fn has_default_priority(&self) -> bool {
        self.datagram_type & 0x08 != 0
    }

    /// Encode the datagram header, refusing a status the framing cannot carry.
    ///
    /// A datagram states a status only when its type byte sets the status flag
    /// (0x20). With the flag clear there is no status field on the wire, so an
    /// `object_status` of anything but [`ObjectStatus::Normal`] has nowhere to
    /// go: [`Self::encode`] drops it, and the datagram parses back as an
    /// ordinary payload object. An End of Group marker written that way does
    /// not arrive late or malformed — it does not arrive at all, and the
    /// receiver sees a normal object in its place.
    ///
    /// Draft-15 Section 10.3.1 puts the framing side plainly — "The Object
    /// Status field and Object Payload are mutually exclusive" — and Section
    /// 10.2.1.1 the conformance side: "Any object with a status code other than
    /// zero MUST have an empty payload." Between them there is no datagram that
    /// carries a non-zero status and a payload, so the pair being refused here
    /// is not one this encoder merely declines to spell.
    ///
    /// [`ObjectStatus::Normal`] with the flag clear is not that case and is
    /// accepted. It is the status the encoding elides for every datagram that
    /// carries a payload, so stating it asks for exactly the bytes leaving it
    /// out asks for, and nothing is lost.
    ///
    /// Errors with [`CodecError::InvalidField`] on the lossy combination,
    /// before any byte is written, so a refused header leaves `buf` untouched.
    /// It also refuses a type byte Section 10.3.1 Table 5 does not assign, so
    /// this encoder cannot emit a datagram its own decoder — or a conforming
    /// peer — must close the session over.
    ///
    /// The extension block is refused on the same terms the type byte governs
    /// it, in both directions. A type announcing extensions must carry some:
    /// Section 10.3.1 states that "If an endpoint receives a datagram with
    /// Extensions Present as 'Yes' and a Extension Headers Length of 0, it MUST
    /// close the session with a PROTOCOL_VIOLATION", so a zero-length block
    /// under that type is a datagram no peer may accept. A type announcing none
    /// cannot carry any, because [`Self::encode`] would drop the bytes in
    /// silence.
    ///
    /// That first rule belongs to datagrams alone. Section 10.4.2 says the
    /// opposite of a subgroup stream — "Objects with no extensions set Extension
    /// Headers Length to 0" — because there the type byte is fixed for the whole
    /// stream and a zero-length block is the only way one object among many can
    /// say it has no extensions. Applying the datagram rule to a subgroup object
    /// would refuse frames the draft spells out.
    ///
    /// Also refused: an extension block beside a status other than Normal, per
    /// Section 10.2.1.2. [`Self::decode`] still parses such a datagram, so a
    /// capture containing one stays readable; see
    /// `check_extensions_against_status_on_encode`.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        if !self.is_status() && matches!(self.object_status, Some(s) if s != ObjectStatus::Normal) {
            return Err(CodecError::InvalidField);
        }
        if !datagram_type_is_assigned(self.datagram_type as u64) {
            return Err(CodecError::UnknownDatagramType(self.datagram_type as u64));
        }
        if self.has_extensions() {
            if self.extension_headers.is_empty() {
                return Err(CodecError::InvalidField);
            }
        } else if !self.extension_headers.is_empty() {
            return Err(CodecError::InvalidField);
        }
        check_extensions_against_status_on_encode(
            self.effective_status().map(|s| s.as_u64()),
            if self.has_extensions() { self.extension_headers.len() as u64 } else { 0 },
        )?;
        self.encode(buf);
        Ok(())
    }

    /// The status this datagram resolves to, or `None` when its framing gives
    /// it none to resolve.
    ///
    /// The type byte decides. With the status bit set the field is on the wire
    /// and an unset [`Self::object_status`] is written as
    /// [`ObjectStatus::Normal`]; with the bit clear the datagram carries a
    /// payload, and the status of an object that carries a payload is Normal —
    /// draft-15 Section 10.2.1.1 says "This status is implicit for any non-zero
    /// length object". `None` is that implicit Normal, which is why a caller
    /// asking what a datagram's status is may not read [`Self::object_status`]
    /// directly.
    fn effective_status(&self) -> Option<ObjectStatus> {
        if self.is_status() {
            Some(self.object_status.unwrap_or(ObjectStatus::Normal))
        } else {
            None
        }
    }

    /// Whether this datagram's status is allowed to carry the extension headers
    /// it has.
    ///
    /// The datagram half of the rule [`SubgroupObject::extensions_permitted`]
    /// answers for a subgroup object; draft-15 Section 10.3.1 builds the
    /// datagram's extension block out of the same structure Section 10.2.1.2
    /// defines, so the rule covers both carriers.
    ///
    /// [`Self::decode`] reports this rather than refusing, because the datagram
    /// is well framed and a codec that could not read one could not reproduce a
    /// capture containing it. [`Self::encode_checked`] does refuse it — that is
    /// the one direction with no such excuse, and a plain [`Self::encode`]
    /// stands beside it when verbatim reproduction is what is wanted.
    pub fn extensions_permitted(&self) -> bool {
        if !self.has_extensions() || self.extension_headers.is_empty() {
            return true;
        }
        self.effective_status().unwrap_or(ObjectStatus::Normal) == ObjectStatus::Normal
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
    /// itself. An `object_status` set while the type byte leaves the status
    /// flag clear is discarded here without a word. Prefer
    /// [`Self::encode_checked`], which refuses that combination instead of
    /// resolving it.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.datagram_type as usize).encode(buf);
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        if self.has_object_id() {
            self.object_id.encode(buf);
        }
        if !self.has_default_priority() {
            // The type byte is the authority on presence. A `None` here under a
            // type whose `0x08` bit is clear writes a zero rather than dropping
            // the byte: omitting it would leave the peer reading the first
            // extension-length or status varint as a priority.
            buf.put_u8(self.publisher_priority.unwrap_or(0));
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

    /// Decode a datagram header from `buf`.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        // Compared as the full varint, not truncated to `u8`: a type of `0x100`
        // narrows to `0x00` and would be read as an ordinary object datagram, so
        // a greased or future type would be silently mis-parsed rather than
        // closing the session.
        let type_value = VarInt::decode(buf)?.into_inner();
        if !datagram_type_is_assigned(type_value) {
            return Err(CodecError::UnknownDatagramType(type_value));
        }
        let datagram_type = type_value as u8;
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let object_id =
            if datagram_type & 0x04 == 0 { VarInt::decode(buf)? } else { VarInt::from_usize(0) };
        let publisher_priority = if datagram_type & 0x08 == 0 {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        } else {
            None
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

// ── Fetch stream headers ───────────────────────────────────

/// Fetch stream header for draft-15.
///
/// Stream type is 0x05. Only contains a request_id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchHeader {
    pub request_id: VarInt,
}

/// The unidirectional stream type draft-15 Section 10.4.4 gives a fetch stream.
const FETCH_STREAM_TYPE: u64 = 0x05;

/// Which failure a leading unidirectional stream type that is not the one a
/// reader wants is.
///
/// Section 10: "An endpoint that receives an unknown stream or datagram type
/// MUST close the session." One sentence, two tables. The stream table assigns
/// FETCH_HEADER and the subgroup types [`subgroup_type_is_assigned`] describes;
/// everything outside them is unknown at the head of a stream, and the session
/// ends.
///
/// Both assigned kinds are what the [`CodecError::InvalidField`] arm is for: a
/// fetch stream reaching the subgroup reader, or a subgroup stream reaching the
/// fetch reader, is a value this draft defines, and the disagreement is with
/// the reader that was called rather than with the draft. Reporting it as
/// unknown would end sessions over streams draft-15 permits.
///
/// The datagram reader needs no such helper. Its table shares no value with the
/// stream table, so every type it rejects is one no table assigns and the
/// answer is always [`CodecError::UnknownDatagramType`].
fn stream_type_error(raw: u64) -> CodecError {
    if raw == FETCH_STREAM_TYPE || subgroup_type_is_assigned(raw) {
        CodecError::InvalidField
    } else {
        CodecError::UnknownStreamType(raw)
    }
}

impl FetchHeader {
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(FETCH_STREAM_TYPE as usize).encode(buf);
        self.request_id.encode(buf);
    }

    /// Decode the header.
    ///
    /// Errors with [`CodecError::UnknownStreamType`] when the stream table does
    /// not assign the leading type, which this draft answers with a close, and
    /// with [`CodecError::InvalidField`] for the subgroup types, which it does
    /// assign. `stream_type_error` draws that line.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let stream_type = VarInt::decode(buf)?.into_inner();
        if stream_type != FETCH_STREAM_TYPE {
            return Err(stream_type_error(stream_type));
        }
        let request_id = VarInt::decode(buf)?;
        Ok(Self { request_id })
    }
}

// ── Fetch objects (stateful) ───────────────────────────────

/// How a draft-15 fetch object carries its Subgroup ID.
///
/// The two least significant bits of the Serialization Flags are one field,
/// not two independent flags: draft-15 Section 10.4.4, Table 7 gives all four
/// of their values a meaning, and only one of them puts a Subgroup ID on the
/// wire. Reading either bit on its own gets the wrong answer for half the
/// values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubgroupIdEncoding {
    /// `0x00`: the Subgroup ID is zero, whatever the preceding object's was.
    Zero,
    /// `0x01`: the Subgroup ID is the prior object's.
    SameAsPrior,
    /// `0x02`: the Subgroup ID is the prior object's plus one.
    PriorPlusOne,
    /// `0x03`: the Subgroup ID follows as a varint.
    Present,
}

impl SubgroupIdEncoding {
    /// Read the two-bit field out of a Serialization Flags byte.
    pub fn from_flags(flags: u8) -> Self {
        match flags & 0x03 {
            0x00 => SubgroupIdEncoding::Zero,
            0x01 => SubgroupIdEncoding::SameAsPrior,
            0x02 => SubgroupIdEncoding::PriorPlusOne,
            _ => SubgroupIdEncoding::Present,
        }
    }

    /// The bit pattern this encoding occupies in a Serialization Flags byte.
    pub fn as_bits(self) -> u8 {
        match self {
            SubgroupIdEncoding::Zero => 0x00,
            SubgroupIdEncoding::SameAsPrior => 0x01,
            SubgroupIdEncoding::PriorPlusOne => 0x02,
            SubgroupIdEncoding::Present => 0x03,
        }
    }

    /// Whether resolving a Subgroup ID under this encoding needs the object
    /// before it on the stream.
    ///
    /// [`SubgroupIdEncoding::Zero`] does not, which is what makes it the one
    /// implicit form a stream's first object may use.
    pub fn references_prior(self) -> bool {
        matches!(self, SubgroupIdEncoding::SameAsPrior | SubgroupIdEncoding::PriorPlusOne)
    }
}

/// One object on a draft-15 fetch stream, without its payload.
///
/// Draft-15 Section 10.4.4 gives fetch objects a leading Serialization Flags
/// byte that says which of the object's fields are on the wire; every field it
/// omits is taken from, or counted from, the object before it on the same
/// stream. An object therefore cannot be decoded on its own, and the fields
/// below are the resolved absolute values rather than whatever the wire spelled
/// out — reading them needs the running state a [`FetchObjectReader`] carries.
///
/// `serialization_flags` is kept beside the resolved values so that an object
/// re-encodes to the bytes it was decoded from. One object has as many
/// encodings as there are flag bytes that resolve to it, and choosing one on
/// the caller's behalf would rewrite a stream a relay is meant to forward
/// unchanged.
///
/// The bits, from Section 10.4.4, Tables 7 and 8:
/// - `& 0x03`: how the Subgroup ID is carried; see [`SubgroupIdEncoding`]
/// - `& 0x04`: Object ID field present, else the prior object's ID plus one
/// - `& 0x08`: Group ID field present, else the prior object's Group ID
/// - `& 0x10`: Publisher Priority field present, else the prior object's
/// - `& 0x20`: Extensions field present
/// - `& 0xc0`: unassigned, and Table 8 makes either bit a protocol violation
///
/// The payload is deliberately not part of this type: an object's declared
/// length is the last thing before its bytes, so a caller that forwards
/// payloads verbatim can read the framing and then move `payload_length` bytes
/// without ever copying them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObjectHeader {
    /// Raw Serialization Flags byte, as decoded or as it is to be written.
    pub serialization_flags: u8,
    /// Resolved absolute Group ID.
    pub group_id: VarInt,
    /// Resolved absolute Subgroup ID.
    pub subgroup_id: VarInt,
    /// Resolved absolute Object ID.
    pub object_id: VarInt,
    /// Publisher priority for delivery ordering.
    pub publisher_priority: u8,
    /// Raw extension-header bytes, excluding the byte-length prefix that
    /// precedes them on the wire. Empty when the flags do not set the
    /// extensions bit, or when the block is present but zero-length. Opaque:
    /// [`FetchObjectReader::write_object_header`] re-emits the prefix and these
    /// bytes verbatim.
    pub extension_headers: Vec<u8>,
    /// Payload length as encoded on the wire. Zero when the object is a
    /// status-only object.
    pub payload_length: VarInt,
    /// Object status; `Some` when `payload_length == 0`.
    ///
    /// Section 10.4.4: "The Object Status field is only present if the Object
    /// Payload Length is zero." Typed to the statuses draft-15 assigns for the
    /// same reason [`SubgroupObject::object_status`] is: the field cannot hold
    /// a code the draft leaves unassigned, so the encoder needs no check and
    /// cannot emit an object the decoder would refuse.
    ///
    /// `None` on a zero-length object means the same as
    /// [`ObjectStatus::Normal`] and encodes as it; the wire field is not
    /// optional once `payload_length` is zero.
    pub object_status: Option<ObjectStatus>,
}

impl FetchObjectHeader {
    /// How this object's Subgroup ID is carried, from the low two flag bits.
    pub fn subgroup_id_encoding(&self) -> SubgroupIdEncoding {
        SubgroupIdEncoding::from_flags(self.serialization_flags)
    }

    /// Whether the Object ID is on the wire, rather than the prior object's
    /// ID plus one.
    pub fn has_object_id(&self) -> bool {
        self.serialization_flags & 0x04 != 0
    }

    /// Whether the Group ID is on the wire, rather than the prior object's.
    pub fn has_group_id(&self) -> bool {
        self.serialization_flags & 0x08 != 0
    }

    /// Whether the Publisher Priority is on the wire, rather than the prior
    /// object's.
    pub fn has_priority(&self) -> bool {
        self.serialization_flags & 0x10 != 0
    }

    /// Whether an extensions block is on the wire.
    pub fn has_extensions(&self) -> bool {
        self.serialization_flags & 0x20 != 0
    }

    /// Whether any of this object's fields is taken from the object before it
    /// on the stream.
    ///
    /// Draft-15 Section 10.4.4: "If the first Object in the FETCH response uses
    /// a flag that references fields in the prior Object, the Subscriber MUST
    /// close the session with a PROTOCOL_VIOLATION." Four of the flags do so —
    /// two of the Subgroup ID encodings, and the cleared state of the Object
    /// ID, Group ID and Priority bits, each of which means "the prior
    /// object's". The extensions bit does not: it is present or it is not, and
    /// nothing is inherited either way.
    pub fn references_prior_object(&self) -> bool {
        self.subgroup_id_encoding().references_prior()
            || !self.has_object_id()
            || !self.has_group_id()
            || !self.has_priority()
    }

    /// The status this object resolves to.
    ///
    /// Section 10.4.4: "The Object Status field is only present if the Object
    /// Payload Length is zero." An object declaring a length is therefore
    /// [`ObjectStatus::Normal`] whatever [`Self::object_status`] holds, on the
    /// reading Section 10.2.1.1 gives Normal: "This status is implicit for any
    /// non-zero length object."
    pub fn status(&self) -> ObjectStatus {
        if self.payload_length.into_inner() == 0 {
            self.object_status.unwrap_or(ObjectStatus::Normal)
        } else {
            ObjectStatus::Normal
        }
    }

    /// Whether this object's status is allowed to carry the extension headers
    /// it has.
    ///
    /// The fetch half of the rule [`SubgroupObject::extensions_permitted`]
    /// answers, and the same one: Section 10.4.4 builds a fetch object's
    /// Extensions field out of the structure Section 10.2.1.2 defines, and that
    /// section is where the rule sits — "Any Object with status Normal can have
    /// extension headers. If an endpoint receives extension headers on Objects
    /// with status that is not Normal, it MUST close the session with a
    /// PROTOCOL_VIOLATION."
    /// Draft-15 is the only draft where a fetch object can state this
    /// violation, which is why no counterpart to this exists on drafts 16 and
    /// later rather than one that is always `true`. Section 10.4.4 gives this
    /// draft's fetch object an Object Status field — "The Object Status field
    /// is only present if the Object Payload Length is zero" — and its
    /// extensions bit, Table 8's `0x20`, is independent of every other flag, so
    /// the two can appear together. Drafts 16 and later remove the field
    /// outright, draft-16 Section 10.2.1.1: "The Object Status is a field that
    /// is only present in objects that are delivered via a SUBSCRIPTION, and is
    /// absent in Objects delivered via a FETCH." A fetch object there has no
    /// status to disagree with, so the rule has nothing to bite on.
    ///
    /// [`FetchObjectReader`] reports this rather than refusing it, for the
    /// reason [`SubgroupObject::extensions_permitted`] sets out: the frame is
    /// well formed and merely non-conforming, and a reader that refused it
    /// could not reproduce a capture containing one.
    pub fn extensions_permitted(&self) -> bool {
        self.extension_headers.is_empty() || self.status() == ObjectStatus::Normal
    }

    /// Serialize this Object's framing, writing only the fields its own
    /// Serialization Flags announce.
    ///
    /// The inverse of [`FetchObjectReader::read_object_header`], and the reason
    /// it is fallible where the subgroup form's is not: this type holds every
    /// field resolved, so the flags rather than the values decide what goes on
    /// the wire. A Group ID held with the 0x08 bit clear is *not* written and
    /// the reader takes the Object as sharing its predecessor's group — which
    /// is silent data loss when the two differ, and correct when they do not.
    /// Nothing here can tell those apart, so the caller settles it by choosing
    /// the flags, and [`FetchObjectWriter`] is what chooses them against a
    /// predecessor.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] for a flags byte with either of the two
    /// bits Section 10.4.4 leaves unassigned, which is the same value
    /// [`FetchObjectReader::read_object_header`] refuses to read — the field is
    /// one fixed byte and not a variable-length integer, so 0x40 and 0x80 are
    /// not wider spellings of anything.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        if self.serialization_flags & 0xc0 != 0 {
            return Err(CodecError::InvalidField);
        }
        buf.put_u8(self.serialization_flags);
        // Field order is Section 10.4.4's, Figure 30: Group ID, Subgroup ID,
        // Object ID, Priority, Extensions.
        if self.has_group_id() {
            self.group_id.encode(buf);
        }
        if self.subgroup_id_encoding() == SubgroupIdEncoding::Present {
            self.subgroup_id.encode(buf);
        }
        if self.has_object_id() {
            self.object_id.encode(buf);
        }
        if self.has_priority() {
            buf.put_u8(self.publisher_priority);
        }
        if self.has_extensions() {
            VarInt::from_usize(self.extension_headers.len()).encode(buf);
            buf.put_slice(&self.extension_headers);
        }
        self.payload_length.encode(buf);
        // A zero-length Object carries a status varint after the length, and a
        // non-zero-length one carries none: the reader reads the field on
        // exactly that test, so writing it on any other would put a byte on the
        // wire the reader would take for payload.
        if self.payload_length.into_inner() == 0 {
            VarInt::from_u64(self.object_status.unwrap_or(ObjectStatus::Normal).as_u64())
                .map_err(|_| CodecError::InvalidField)?
                .encode(buf);
        }
        Ok(())
    }
}

/// Re-encodes resolved fetch Objects onto one FETCH stream.
///
/// The exact inverse of [`FetchObjectReader`], and it exists for one caller:
/// something that has read a stream and is writing a different stream from the
/// same Objects. Draft-15 Section 10.4.4 lets an Object leave out its Group
/// ID, Object ID, Subgroup ID and Priority and take the prior Object's, so
/// removing an Object changes what the Objects after it are read against: a
/// field the survivor left off has to appear, and a flag bit with it.
///
/// Every field draft-15 puts on the wire is the absolute value rather than a
/// difference — the deltas arrive at draft-18. What is stateful is the
/// *omission*, and that alone makes removal a re-encode rather than a deletion.
///
/// # Why this is not a general encoder
///
/// Every Object it writes came off a stream, so the caller holds the Object's
/// own header with both its resolved values and the flags it arrived under.
/// Those flags are the preference: wherever the original shape still says the
/// same thing against the new predecessor it is kept, so a stream with nothing
/// removed is reproduced byte for byte.
#[derive(Debug, Clone, Default)]
pub struct FetchObjectWriter {
    prior: Option<PriorFetchObject>,
}

impl FetchObjectWriter {
    /// A writer positioned before the first Object of a fetch stream, with no
    /// prior Object for anything to be written against.
    pub fn new() -> Self {
        Self::default()
    }

    /// The header that encodes `original`'s resolved values against everything
    /// written so far.
    ///
    /// Does not advance the writer — [`Self::write_object_header`] is the call
    /// that does both.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] for a flags byte with an unassigned bit.
    pub fn header_for(
        &self,
        original: &FetchObjectHeader,
    ) -> Result<FetchObjectHeader, CodecError> {
        if original.serialization_flags & 0xc0 != 0 {
            return Err(CodecError::InvalidField);
        }
        let group_id = original.group_id.into_inner();
        let subgroup_id = original.subgroup_id.into_inner();
        let object_id = original.object_id.into_inner();

        // Each field is written when the Object wrote it, and written anyway
        // when leaving it off would now say something else. Keeping the
        // Object's own choice is what reproduces an untouched stream byte for
        // byte; the second half is what a removal forces.
        let mut flags = 0u8;
        if original.has_group_id() || self.prior.map(|p| p.group_id) != Some(group_id) {
            flags |= 0x08;
        }
        if original.has_object_id()
            || self.prior.and_then(|p| p.object_id.checked_add(1)) != Some(object_id)
        {
            flags |= 0x04;
        }
        if original.has_priority()
            || self.prior.map(|p| p.publisher_priority) != Some(original.publisher_priority)
        {
            flags |= 0x10;
        }
        if original.has_extensions() {
            flags |= 0x20;
        }
        flags |= self.subgroup_bits(original, subgroup_id).as_bits();

        Ok(FetchObjectHeader {
            serialization_flags: flags,
            group_id: original.group_id,
            subgroup_id: original.subgroup_id,
            object_id: original.object_id,
            publisher_priority: original.publisher_priority,
            extension_headers: original.extension_headers.clone(),
            payload_length: original.payload_length,
            object_status: original.object_status,
        })
    }

    /// Which Subgroup ID encoding says `subgroup_id` against this predecessor.
    ///
    /// The Object's own encoding is tried first, so a run that inherited its
    /// Subgroup ID keeps inheriting it and its bytes do not move. Only when the
    /// predecessor changed under it is a different one chosen, and then the
    /// cheapest that names the right number.
    fn subgroup_bits(&self, original: &FetchObjectHeader, subgroup_id: u64) -> SubgroupIdEncoding {
        let inherits = self.prior.map(|p| p.subgroup_id) == Some(subgroup_id);
        let successor =
            self.prior.is_some_and(|p| p.subgroup_id.checked_add(1) == Some(subgroup_id));
        let kept = match original.subgroup_id_encoding() {
            SubgroupIdEncoding::Zero if subgroup_id == 0 => Some(SubgroupIdEncoding::Zero),
            SubgroupIdEncoding::SameAsPrior if inherits => Some(SubgroupIdEncoding::SameAsPrior),
            SubgroupIdEncoding::PriorPlusOne if successor => Some(SubgroupIdEncoding::PriorPlusOne),
            SubgroupIdEncoding::Present => Some(SubgroupIdEncoding::Present),
            _ => None,
        };
        match kept {
            Some(encoding) => encoding,
            None if subgroup_id == 0 => SubgroupIdEncoding::Zero,
            None if inherits => SubgroupIdEncoding::SameAsPrior,
            None if successor => SubgroupIdEncoding::PriorPlusOne,
            None => SubgroupIdEncoding::Present,
        }
    }

    /// Encode `original`'s resolved values against everything written so far
    /// and advance.
    ///
    /// Writes the framing only. The payload is `payload_length` bytes and is
    /// the caller's to copy, unchanged.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] for a flags byte with an unassigned bit;
    /// the writer is left untouched when this happens.
    pub fn write_object_header(
        &mut self,
        original: &FetchObjectHeader,
        out: &mut impl BufMut,
    ) -> Result<FetchObjectHeader, CodecError> {
        let header = self.header_for(original)?;
        header.encode(out)?;
        self.advance(&header);
        Ok(header)
    }

    /// Record what was written as the predecessor of whatever comes next.
    ///
    /// Every field draft-15 puts on a fetch object's wire is the absolute
    /// value, so this reads them straight off the header rather than resolving
    /// anything.
    ///
    /// Public because a re-emitting caller has a second way of putting a frame
    /// on the wire: when the framing it arrived in still encodes the same
    /// meaning against the frame before it, its own bytes are forwarded
    /// untouched — no header is produced and nothing is copied. The writer
    /// still has to move, or the frame after it is encoded against a
    /// predecessor one frame stale. `written` is then the Object's own header, which is
    /// what was put on the wire.
    pub fn advance(&mut self, written: &FetchObjectHeader) {
        self.prior = Some(PriorFetchObject {
            group_id: written.group_id.into_inner(),
            subgroup_id: written.subgroup_id.into_inner(),
            object_id: written.object_id.into_inner(),
            publisher_priority: written.publisher_priority,
        });
    }
}

/// The fields a draft-15 fetch object leaves to its successor to inherit.
#[derive(Debug, Clone, Copy)]
struct PriorFetchObject {
    group_id: u64,
    subgroup_id: u64,
    object_id: u64,
    publisher_priority: u8,
}

/// Stateful reader/writer for the objects on one draft-15 fetch stream.
///
/// Holds the fields of the object last read or written, which is what the next
/// object's Serialization Flags may refer to. One reader belongs to one stream:
/// draft-15 Section 10.4.4 counts "the prior Object" along the stream, so
/// sharing a reader between streams, or restarting one mid-stream, resolves
/// later objects onto the wrong group, subgroup, ID or priority without
/// producing an error anywhere.
///
/// A fresh reader has no prior object, which is exactly the state in which the
/// draft's protocol violation applies — see
/// [`FetchObjectHeader::references_prior_object`].
#[derive(Debug, Clone, Default)]
pub struct FetchObjectReader {
    prior: Option<PriorFetchObject>,
}

impl FetchObjectReader {
    /// Build a reader for the objects following a fetch stream's header.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next object's framing, leaving its payload in `buf`.
    ///
    /// Consumes the Serialization Flags byte, whichever of the Group ID,
    /// Subgroup ID, Object ID, Priority and Extensions fields that byte says are
    /// present, the Object Payload Length, and the Object Status when that
    /// length is zero. The declared payload bytes are left where they are, so a
    /// caller can forward them without a copy; skipping them is the caller's
    /// job, and skipping the wrong number of them desynchronises every later
    /// object on the stream.
    ///
    /// Errors with [`CodecError::InvalidField`] when the flags set either bit
    /// draft-15 Section 10.4.4, Table 8 leaves unassigned, when the stream's
    /// first object inherits from an object that does not exist, when an
    /// inherited value cannot be represented, or when the Object Status is a
    /// code the draft does not assign.
    pub fn read_object_header(
        &mut self,
        buf: &mut impl Buf,
    ) -> Result<FetchObjectHeader, CodecError> {
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        // Section 10.4.4 writes the field as "Serialization Flags (8)": one
        // fixed byte, not a varint. The two readings only part on the values
        // Table 8 forbids, which is what makes the difference easy to miss —
        // 0x40 and 0x80 are the two- and four-byte varint prefixes, so a varint
        // reader consumes the fields after them as part of the flags and
        // reports a plausible object instead of the violation.
        let serialization_flags = buf.get_u8();
        if serialization_flags & 0xc0 != 0 {
            return Err(CodecError::InvalidField);
        }

        let subgroup_encoding = SubgroupIdEncoding::from_flags(serialization_flags);
        let has_object_id = serialization_flags & 0x04 != 0;
        let has_group_id = serialization_flags & 0x08 != 0;
        let has_priority = serialization_flags & 0x10 != 0;
        let has_extensions = serialization_flags & 0x20 != 0;

        // The first object on the stream has nothing to inherit from, and the
        // draft's answer to being asked anyway is to close the session rather
        // than to invent a zero.
        let inherits = subgroup_encoding.references_prior()
            || !has_object_id
            || !has_group_id
            || !has_priority;
        if inherits && self.prior.is_none() {
            return Err(CodecError::InvalidField);
        }
        let prior = self.prior;

        // Field order is Section 10.4.4's, Figure 30: Group ID, then Subgroup
        // ID, then Object ID, then Priority, then Extensions. Only the fields
        // the flags announce are on the wire, so resolving out of order would
        // read one field's bytes as another's.
        let group_id = if has_group_id {
            VarInt::decode(buf)?
        } else {
            let prior = prior.ok_or(CodecError::InvalidField)?;
            VarInt::from_u64(prior.group_id).map_err(|_| CodecError::InvalidField)?
        };

        let subgroup_id = match subgroup_encoding {
            SubgroupIdEncoding::Zero => VarInt::from_usize(0),
            SubgroupIdEncoding::SameAsPrior => {
                let prior = prior.ok_or(CodecError::InvalidField)?;
                VarInt::from_u64(prior.subgroup_id).map_err(|_| CodecError::InvalidField)?
            }
            SubgroupIdEncoding::PriorPlusOne => {
                let prior = prior.ok_or(CodecError::InvalidField)?;
                let next = prior.subgroup_id.checked_add(1).ok_or(CodecError::InvalidField)?;
                VarInt::from_u64(next).map_err(|_| CodecError::InvalidField)?
            }
            SubgroupIdEncoding::Present => VarInt::decode(buf)?,
        };

        let object_id = if has_object_id {
            VarInt::decode(buf)?
        } else {
            let prior = prior.ok_or(CodecError::InvalidField)?;
            let next = prior.object_id.checked_add(1).ok_or(CodecError::InvalidField)?;
            VarInt::from_u64(next).map_err(|_| CodecError::InvalidField)?
        };

        let publisher_priority = if has_priority {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            buf.get_u8()
        } else {
            prior.ok_or(CodecError::InvalidField)?.publisher_priority
        };

        let extension_headers = if has_extensions {
            // Section 10.4.4 defers to Section 10.2.1.2 here, so the block is
            // the same byte-length-prefixed opaque blob subgroup objects carry.
            let ext_len = VarInt::decode(buf)?.into_inner() as usize;
            crate::types::read_bytes(buf, ext_len)?
        } else {
            Vec::new()
        };

        let payload_length = VarInt::decode(buf)?;
        let object_status = if payload_length.into_inner() == 0 {
            Some(decoded_status(VarInt::decode(buf)?.into_inner())?)
        } else {
            None
        };
        self.prior = Some(PriorFetchObject {
            group_id: group_id.into_inner(),
            subgroup_id: subgroup_id.into_inner(),
            object_id: object_id.into_inner(),
            publisher_priority,
        });

        Ok(FetchObjectHeader {
            serialization_flags,
            group_id,
            subgroup_id,
            object_id,
            publisher_priority,
            extension_headers,
            payload_length,
            object_status,
        })
    }

    /// Serialize an object's framing, leaving its payload to the caller.
    ///
    /// Writes exactly the fields `header.serialization_flags` announces, and
    /// stops after the Object Payload Length — or, when that length is zero,
    /// after the Object Status. The caller appends `payload_length` payload
    /// bytes; the length is already on the wire by then, so appending a
    /// different number of them frames an object no reader can parse.
    ///
    /// The flags are taken as the authority on what reaches the wire, which
    /// means a header whose resolved fields disagree with its own flags cannot
    /// be written faithfully. Every such disagreement is refused with
    /// [`CodecError::InvalidField`] rather than resolved:
    ///
    /// - a field the flags omit whose value is not the one the omission
    ///   implies — a Group ID that is not the prior object's, a Subgroup ID
    ///   that is not what the two-bit encoding resolves to, an Object ID that
    ///   is not the prior object's plus one, a Priority that is not the prior
    ///   object's. Written anyway, each would arrive as the value the flags
    ///   imply, and the object the peer sees would be a different object.
    /// - extension bytes with the extensions bit clear, which would be dropped
    ///   in silence. Draft-15 Section 10.2.1.2 requires relays to forward
    ///   extensions they do not understand unchanged, so dropping them is not
    ///   a smaller loss than mis-stating an ID.
    /// - a status other than [`ObjectStatus::Normal`] on an object with a
    ///   non-zero payload length. Section 10.4.4 puts the status field on the
    ///   wire only when that length is zero, and Section 10.2.1.1 the
    ///   conformance side: "Any object with a status code other than zero MUST
    ///   have an empty payload." There is no such object to write.
    ///   [`ObjectStatus::Normal`] alongside a payload is not that case and is
    ///   accepted: it is the status the encoding elides for every object that
    ///   carries bytes, so stating it asks for exactly the bytes leaving it out
    ///   asks for.
    ///
    /// Not refused: extension bytes on an object whose resolved status is not
    /// [`ObjectStatus::Normal`], which Section 10.2.1.2 forbids. As on a
    /// subgroup stream this is the only writer a fetch object has, and the
    /// frame encodes and reads back exactly, so refusing it would cost the
    /// ability to reproduce a capture rather than prevent anything.
    ///
    /// Also refused: flags setting either bit Table 8 leaves unassigned, and a
    /// first object on the stream that inherits from an object that does not
    /// exist.
    ///
    /// Every check runs before a byte is written, so a refused header leaves
    /// `buf` untouched rather than half an object the next write would run
    /// into, and leaves the reader's prior-object state as it was.
    pub fn write_object_header(
        &mut self,
        header: &FetchObjectHeader,
        buf: &mut impl BufMut,
    ) -> Result<(), CodecError> {
        if header.serialization_flags & 0xc0 != 0 {
            return Err(CodecError::InvalidField);
        }
        if header.payload_length.into_inner() != 0
            && matches!(header.object_status, Some(s) if s != ObjectStatus::Normal)
        {
            return Err(CodecError::InvalidField);
        }
        if !header.has_extensions() && !header.extension_headers.is_empty() {
            return Err(CodecError::InvalidField);
        }
        // As on a subgroup stream, extension headers beside a non-Normal status
        // are not refused here: they encode and read back exactly, this is the
        // only writer a fetch object has, and a capture containing one has to
        // stay reproducible. See `SubgroupObjectReader::write_object`.
        if header.references_prior_object() && self.prior.is_none() {
            return Err(CodecError::InvalidField);
        }
        let prior = self.prior;
        if !header.has_group_id() {
            let prior = prior.ok_or(CodecError::InvalidField)?;
            if header.group_id.into_inner() != prior.group_id {
                return Err(CodecError::InvalidField);
            }
        }
        let subgroup_id = header.subgroup_id.into_inner();
        match header.subgroup_id_encoding() {
            SubgroupIdEncoding::Zero => {
                if subgroup_id != 0 {
                    return Err(CodecError::InvalidField);
                }
            }
            SubgroupIdEncoding::SameAsPrior => {
                let prior = prior.ok_or(CodecError::InvalidField)?;
                if subgroup_id != prior.subgroup_id {
                    return Err(CodecError::InvalidField);
                }
            }
            SubgroupIdEncoding::PriorPlusOne => {
                let prior = prior.ok_or(CodecError::InvalidField)?;
                let next = prior.subgroup_id.checked_add(1).ok_or(CodecError::InvalidField)?;
                if subgroup_id != next {
                    return Err(CodecError::InvalidField);
                }
            }
            SubgroupIdEncoding::Present => {}
        }
        if !header.has_object_id() {
            let prior = prior.ok_or(CodecError::InvalidField)?;
            let next = prior.object_id.checked_add(1).ok_or(CodecError::InvalidField)?;
            if header.object_id.into_inner() != next {
                return Err(CodecError::InvalidField);
            }
        }
        if !header.has_priority() {
            let prior = prior.ok_or(CodecError::InvalidField)?;
            if header.publisher_priority != prior.publisher_priority {
                return Err(CodecError::InvalidField);
            }
        }

        buf.put_u8(header.serialization_flags);
        if header.has_group_id() {
            header.group_id.encode(buf);
        }
        if header.subgroup_id_encoding() == SubgroupIdEncoding::Present {
            header.subgroup_id.encode(buf);
        }
        if header.has_object_id() {
            header.object_id.encode(buf);
        }
        if header.has_priority() {
            buf.put_u8(header.publisher_priority);
        }
        if header.has_extensions() {
            VarInt::from_usize(header.extension_headers.len()).encode(buf);
            buf.put_slice(&header.extension_headers);
        }
        header.payload_length.encode(buf);
        if header.payload_length.into_inner() == 0 {
            // Zero length means a status object, and the status is not optional
            // on the wire; an unset one is Normal.
            let status = header.object_status.unwrap_or(ObjectStatus::Normal);
            VarInt::from_usize(status.as_u64() as usize).encode(buf);
        }

        self.prior = Some(PriorFetchObject {
            group_id: header.group_id.into_inner(),
            subgroup_id,
            object_id: header.object_id.into_inner(),
            publisher_priority: header.publisher_priority,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonically encoded subgroup stream vectors from
    /// `test-vectors/transport/draft15/codec/data-streams/subgroup.json`.
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
        "120105800004deadbeef",
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
    /// leaves the object-id (0x04) and extensions (0x01) flags clear, so the
    /// layout is `type, track_alias, group_id, object_id, priority, status`.
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
    /// assertion `left == right` failed: ObjectDoesNotExist on the subgroup wire
    ///   left: [0, 0, 0]
    ///  right: [0, 0, 1]
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
    /// contains every code draft-15 assigns, the gap inside that range (0x2)
    /// and the codes later drafts moved (0x1, 0x5). The expected set is read
    /// from [`ObjectStatus::ALL`] rather than written out here, so reassigning
    /// a code moves both halves of the test at once.
    ///
    /// Observed by teaching `ObjectStatus::from_u64` to answer `Some` for a
    /// code that is not in `ALL` — 0x05, which drafts 07-10 assigned and
    /// draft-15 does not, mapped onto an existing variant — which fails this
    /// with:
    ///
    /// ```text
    /// assertion `left == right` failed: subgroup read_object on status 0x5: Ok(SubgroupObject { object_id: VarInt(0), extension_headers: [], payload_length: VarInt(0), object_status: Some(EndOfTrack), payload: [] })
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

    /// A fetch object reports the extensions-beside-a-status rule the subgroup
    /// and datagram carriers already reported.
    /// Draft-15 is the only draft on which this is expressible: from
    /// draft-16 Section 10.2.1.1 the Object Status field is "absent in Objects
    /// delivered via a FETCH", so there is no status for extensions to sit
    /// beside. All four objects below are well formed and all four decode — the
    /// predicate is the only thing that separates them, which is the whole
    /// point of reporting rather than refusing.
    ///
    /// Inverting the predicate's `||` to `&&` fails this at the second case,
    /// `[1c0000000003] End of Group with no extensions is fine: expected true,
    /// got false`, and fails
    /// `fetch_object_status_is_normal_whenever_a_payload_is_declared` beside
    /// it.
    #[test]
    fn fetch_objects_report_extensions_beside_a_non_normal_status() {
        // flags 0x3c: Subgroup ID zero, Group ID / Object ID / Priority and an
        // extensions block all present. flags 0x1c is the same without the
        // extensions block.
        let cases: [(&str, bool, &str); 4] = [
            (
                "3c000000023c010003",
                false,
                "a two-byte extension block beside End of Group is the violation",
            ),
            ("1c0000000003", true, "End of Group with no extensions is fine"),
            (
                "3c000000000003",
                true,
                "a present but zero-length block carries nothing, so nothing is beside the status",
            ),
            ("3c000000023c0104", true, "a normal object may carry extensions"),
        ];

        for (vector, permitted, why) in cases {
            let bytes = hex(vector);
            let mut cursor = &bytes[..];
            let header = FetchObjectReader::new()
                .read_object_header(&mut cursor)
                .unwrap_or_else(|e| panic!("[{vector}] {why}: decode failed with {e:?}"));
            assert_eq!(
                header.extensions_permitted(),
                permitted,
                "[{vector}] {why}: expected {permitted}, got {}",
                header.extensions_permitted(),
            );
        }
    }

    /// A fetch object's status resolves the way a subgroup object's does: the
    /// field is on the wire only under a zero payload length, so an object
    /// declaring bytes is Normal whatever the field would have said.
    #[test]
    fn fetch_object_status_is_normal_whenever_a_payload_is_declared() {
        let bytes = hex("3c000000023c0104");
        let mut cursor = &bytes[..];
        let header = FetchObjectReader::new().read_object_header(&mut cursor).unwrap();
        assert_eq!(header.object_status, None, "no status field follows a non-zero length");
        assert_eq!(header.status(), ObjectStatus::Normal);

        // Assembled by hand rather than decoded: the wire cannot put a status
        // beside a payload, but the struct's fields are public and a caller
        // porting an object across drafts can set both.
        let contradictory =
            FetchObjectHeader { object_status: Some(ObjectStatus::EndOfGroup), ..header };
        assert_eq!(
            contradictory.status(),
            ObjectStatus::Normal,
            "a declared payload wins over a status the wire could not have carried",
        );
        assert!(contradictory.extensions_permitted());
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

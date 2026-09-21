//! Draft-neutral object framing for MoQT data streams.
//!
//! [`AnySubgroupObjectReader`],
//! [`AnySubgroupObjectWriter`],
//! [`AnyFetchObjectReader`] and
//! [`AnyFetchObjectWriter`]
//! present one API over drafts' object encodings. The values they
//! produce — `AnySubgroupObject`, `AnySubgroupObjectMeta`, `AnyFetchObject`,
//! `AnyFetchObjectMeta` — are plain structs of primitives, so a caller can
//! address objects without naming a `draftNN` type. All of them are also
//! re-exported from [`crate::dispatch`].
//!
//! Objects on drafts 07-13 are standalone: absolute Object IDs, and (on
//! drafts 11-13) an extension block whose presence is fixed by the stream
//! type. Drafts 14-21 delta-encode Object IDs against the previous object on
//! the stream. Both are constructed from the stream's header and read one
//! object at a time, so the difference stays inside this module.
//!
//! Fetch streams split the same way, at a different draft. Through draft-14 a
//! fetch object spells out its Group ID, Subgroup ID, Object ID and Publisher
//! Priority on every object, so each one stands alone. Drafts 15-21 put a
//! Serialization Flags field first and let it leave any of those four off the
//! wire, meaning "the prior object's" — and from draft-18 the two ID fields
//! that remain are differences rather than values. So a fetch object on those
//! drafts is only meaningful in stream order, and
//! [`AnyFetchObjectReader`]
//! carries the running state that resolves it. The
//! values it produces are absolute on every draft.
//!
//! # Partial buffers
//!
//! Reader state after an error is unspecified. A caller that may be handed an
//! incomplete object clones the reader, decodes against the clone, and
//! overwrites the real reader only once the decode succeeds.

use bytes::{Buf, BufMut};

use crate::dispatch::{AnyFetchHeader, AnySubgroupHeader};
use crate::error::CodecError;
use crate::varint::VarInt;
use crate::version::DraftVersion;

// ── Draft-neutral object values ─────────────────────────────

/// One object read from a subgroup data stream, normalised across drafts.
///
/// Field semantics are identical on every draft 07-21; the per-draft wire
/// differences (absolute vs delta object IDs, count- vs length-prefixed
/// extension blocks, typed vs raw status codes) are resolved by
/// [`AnySubgroupObjectReader`] before this value is produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnySubgroupObject {
    /// Absolute Object ID. Already resolved from delta encoding on drafts
    /// 14-21; copied verbatim on drafts 07-13.
    pub object_id: u64,
    /// The extension-header (draft-17+: "property") block's contents,
    /// excluding any length or count prefix. Empty when the draft has no
    /// extension block, when the enclosing header's extensions bit is clear,
    /// or when the block is present but zero-length.
    ///
    /// Opaque and never re-parsed by this crate, and a verbatim copy of the
    /// wire bytes on every draft except draft-08. Draft-08's block is
    /// count-prefixed with no byte length, so its contents can only be
    /// delimited by parsing each extension; the blob is therefore
    /// re-serialized from that parsed form, which re-encodes every varint
    /// minimally. A draft-08 extension whose value arrived as a legal
    /// non-minimal varint is semantically but not byte-identically preserved.
    pub extension_headers: Vec<u8>,
    /// Number of extensions in `extension_headers`. `Some` only on draft-08,
    /// whose extension block is count-prefixed rather than
    /// byte-length-prefixed, so the count cannot be recovered from the blob
    /// without re-parsing it. `None` on every other draft.
    pub extension_count: Option<u64>,
    /// Object Status as the raw wire code, present only when the payload
    /// length is zero. `None` means a non-empty payload followed and the
    /// status is implicitly Normal.
    ///
    /// Kept as a raw code rather than a typed enum because the assigned set
    /// changes across drafts and this value crosses drafts — a relay reads a
    /// status on one and writes it on another, where the same number may mean
    /// something else or nothing at all. The code is nonetheless always one
    /// the *source* draft assigns: every draft's decoder refuses an unassigned
    /// status, so this field never carries a value its draft's Object Status
    /// section forbids.
    pub status: Option<u64>,
    /// Object payload. Empty when `status` is `Some`.
    pub payload: Vec<u8>,
}

/// The framing of one subgroup object, without its payload.
///
/// Produced by [`AnySubgroupObjectReader::read_object_meta`] for callers that
/// forward an object's bytes verbatim and never inspect the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnySubgroupObjectMeta {
    /// Absolute Object ID, resolved as for [`AnySubgroupObject::object_id`].
    pub object_id: u64,
    /// Declared payload length in bytes. Zero when `status` is `Some`.
    pub payload_length: u64,
    /// Object Status wire code, as for [`AnySubgroupObject::status`].
    pub status: Option<u64>,
    /// Byte length of the extension/property block's contents, excluding its
    /// prefix. Always the length of the blob
    /// [`AnySubgroupObject::extension_headers`] would carry, which on draft-08
    /// is a re-serialized copy rather than the wire bytes.
    pub extension_headers_len: u64,
    /// Total bytes this object occupies on the wire, prefix fields included.
    /// Equals the number of bytes the reader consumed.
    pub wire_len: u64,
}

/// What an End of Range indicator asserts about the Locations it covers.
///
/// Drafts 16-21 let a fetch stream state that a run of Objects was not
/// serialized instead of sending them: one frame names the Location that ends
/// the run, and every Location from the previously serialized Object up to and
/// including that one is covered. The indicators are the same frame shape with
/// different claims behind it, and a subscriber may cache the first as a
/// settled gap while it must not cache the others, so they are carried apart
/// rather than merged.
///
/// Never produced on drafts 07-15, which have no such frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyFetchEndOfRange {
    /// The covered Objects do not exist.
    NonExistent,
    /// The covered Objects' status is unknown to the publisher.
    Unknown,
    /// The covered Objects timed out: the relay abandoned them when its
    /// `FILL_TIMEOUT` budget ran out.
    ///
    /// **Draft-20 and later only.** Drafts 16 through 19 have two indicators
    /// and report the same Objects as [`Self::Unknown`], so this variant is
    /// never produced on them — which makes its presence a fact about the
    /// stream's draft as much as about the frame, and is why a receiver cannot
    /// treat the two as interchangeable.
    TimedOut,
}

/// The order a fetch response's groups arrive in.
///
/// Drafts 18 and 19 encode an Object's Group ID as a difference from the
/// previous Object's, and the direction that difference moves is the fetch's
/// Group Order — which is settled by the control exchange that opened the
/// fetch and never appears on the data stream. A reader therefore has to be
/// told, and telling it wrong does not fail to parse: every Object decodes
/// under a Group ID walking the wrong way.
///
/// Ignored on drafts 07-17, whose fetch objects state their Group ID outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyFetchGroupOrder {
    /// Group IDs increase along the stream; a difference is added.
    Ascending,
    /// Group IDs decrease along the stream; a difference is subtracted.
    Descending,
}

/// One frame read from a fetch data stream, normalised across drafts.
///
/// Usually an object. On drafts 16-21 it may instead be an End of Range
/// indicator, which carries a Location and no content — [`Self::end_of_range`]
/// is what tells the two apart, and it is `None` for every object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyFetchObject {
    /// Absolute Group ID. Already resolved against the objects before it on
    /// drafts 15-21, whose fetch objects may omit the field or (on drafts
    /// 18-19) encode it as a difference; copied verbatim on drafts 07-14.
    pub group_id: u64,
    /// Absolute Subgroup ID, resolved as [`Self::group_id`] is. Zero and
    /// meaningless when [`Self::has_subgroup_id`] is `false`.
    pub subgroup_id: u64,
    /// Whether this frame has a Subgroup ID at all.
    ///
    /// `true` on every draft 07-15, and for every End of Range indicator's
    /// predecessor. `false` in two cases drafts 16-21 add: an object whose
    /// Forwarding Preference is Datagram, which has no Subgroup ID anywhere in
    /// its framing, and an End of Range indicator, whose Location is a Group
    /// and Object ID only.
    ///
    /// Kept beside `subgroup_id` rather than folded into it because a relay
    /// that writes this object onto another stream must not invent a Subgroup
    /// ID of zero for an object that has none: on the receiving draft zero is a
    /// real subgroup.
    pub has_subgroup_id: bool,
    /// Absolute Object ID, resolved as [`Self::group_id`] is.
    pub object_id: u64,
    /// Publisher Priority in force for this frame.
    ///
    /// Drafts 15-21 let an object omit the field and take the previous
    /// object's, and an End of Range indicator never carries one. Where
    /// nothing on the stream has stated a priority, this is 128 — the value
    /// every draft 15-21 gives a subscription whose Default Publisher Priority
    /// property is omitted (draft-19 Section 12.4).
    pub publisher_priority: u8,
    /// Extension/property block contents, excluding its prefix. Same
    /// convention as [`AnySubgroupObject::extension_headers`].
    pub extension_headers: Vec<u8>,
    /// Number of extensions; `Some` only on draft-08. Same convention as
    /// [`AnySubgroupObject::extension_count`].
    pub extension_count: Option<u64>,
    /// Object Status wire code, present only when the payload is empty.
    ///
    /// Always `None` on drafts 16-21: those drafts removed the field from
    /// fetch objects entirely, stating that Object Status "is only present in
    /// objects that are delivered via a SUBSCRIPTION, and is absent in Objects
    /// delivered via a FETCH" (draft-19 Section 11.2.1.1). A zero-length fetch
    /// object there is an object with no bytes, not a status object.
    pub status: Option<u64>,
    /// Which End of Range indicator this frame is, or `None` for an object.
    ///
    /// An indicator has a Location and a payload length and nothing else: its
    /// `payload`, `extension_headers` and `status` are empty, its
    /// [`Self::has_subgroup_id`] is `false`, and its `publisher_priority` is
    /// whatever was in force rather than anything it stated.
    pub end_of_range: Option<AnyFetchEndOfRange>,
    /// Object payload. Empty when `status` is `Some`.
    pub payload: Vec<u8>,
}

/// The framing of one fetch frame, without its payload.
///
/// Every field carries the meaning it does on [`AnyFetchObject`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnyFetchObjectMeta {
    /// Absolute Group ID.
    pub group_id: u64,
    /// Absolute Subgroup ID. Meaningless when `has_subgroup_id` is `false`.
    pub subgroup_id: u64,
    /// Whether this frame has a Subgroup ID at all; see
    /// [`AnyFetchObject::has_subgroup_id`].
    pub has_subgroup_id: bool,
    /// Absolute Object ID.
    pub object_id: u64,
    /// Publisher Priority in force for this frame; see
    /// [`AnyFetchObject::publisher_priority`].
    pub publisher_priority: u8,
    /// Declared payload length in bytes.
    pub payload_length: u64,
    /// Object Status wire code; always `None` on drafts 16-21.
    pub status: Option<u64>,
    /// Which End of Range indicator this frame is, or `None` for an object.
    pub end_of_range: Option<AnyFetchEndOfRange>,
    /// Byte length of the extension block's contents, excluding its prefix.
    pub extension_headers_len: u64,
    /// Total bytes this object occupies on the wire.
    pub wire_len: u64,
}

/// The Publisher Priority a fetch frame that states none is read under.
///
/// Drafts 16-21 let an object leave the field off the wire and take the
/// previous object's, and an End of Range indicator carries none at all, so a
/// stream can reach a frame with no priority ever having been stated. Every one
/// of those drafts fixes the same fallback for a subscription that never stated
/// one — draft-19 Section 12.4: "If omitted, the Default Publisher Priority is
/// 128" — and that is what is reported here.
///
/// Draft-15 needs no such fallback: its own reader refuses an object that
/// inherits a priority with nothing to inherit from, and it has no End of Range
/// frame, so every draft-15 fetch object has a priority the stream stated.
///
/// An End of Range indicator reports the Priority still in force from the last
/// Object before it, and this constant only when no Object has preceded it.
/// None of the four drafts decides that. Drafts 17, 18 and 19 say what the
/// *next* Object inherits — draft-19 Section 11.4.4.2: "Prior Priority: The
/// Priority from the last actual Object before the End of Range indicator" —
/// draft-16 does not say even that, and all four agree only that a marker
/// carries no Priority field. So the answer is chosen here, once, for the four
/// of them: [`AnyFetchObject::publisher_priority`] is a `u8` with no way to
/// report "none", and the value in force is one the stream did state, where
/// this constant would be one it never did.
#[cfg(any(
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
const DEFAULT_PUBLISHER_PRIORITY: u8 = 128;

/// Conversions shared by the per-draft glue below. Unused when no draft
/// feature is enabled.
#[allow(dead_code)]
mod conv {
    use super::{AnySubgroupObject, Buf, CodecError};
    use crate::varint::VarInt;

    /// Advance `buf` past `len` bytes without copying them.
    pub fn skip(buf: &mut impl Buf, len: u64) -> Result<(), CodecError> {
        let len = usize::try_from(len).map_err(|_| CodecError::UnexpectedEnd)?;
        if buf.remaining() < len {
            return Err(CodecError::UnexpectedEnd);
        }
        buf.advance(len);
        Ok(())
    }

    /// Copy `len` bytes out of `buf`.
    pub fn take(buf: &mut impl Buf, len: u64) -> Result<Vec<u8>, CodecError> {
        let len = usize::try_from(len).map_err(|_| CodecError::UnexpectedEnd)?;
        crate::types::read_bytes(buf, len)
    }

    /// Wrap a value that must fit the varint range.
    pub fn varint(v: u64) -> Result<VarInt, CodecError> {
        VarInt::from_u64(v).map_err(|_| CodecError::InvalidField)
    }

    /// The status code to encode for `object`, or `None` when a payload
    /// follows instead. An empty payload always carries a status on the
    /// wire, so a missing one defaults to Normal.
    ///
    /// Status `0` with a payload is not a contradiction and is not refused.
    /// Every draft from 07 to 20 assigns `0x0` to Normal, and every one of them
    /// encodes a payload-bearing object by leaving the status field off — the
    /// status is Normal precisely because bytes follow. Saying so explicitly
    /// asks for the same frame as leaving it out, so both answer `None`, and
    /// the byte written is identical either way.
    ///
    /// Any other status with a payload is refused: those are the statuses whose
    /// wire form is a status code standing where the payload would be, so there
    /// is no frame that carries both.
    pub fn status_to_write(object: &AnySubgroupObject) -> Result<Option<u64>, CodecError> {
        match (object.status, object.payload.is_empty()) {
            (Some(0), false) => Ok(None),
            (Some(_), false) => Err(CodecError::InvalidField),
            (Some(code), true) => Ok(Some(code)),
            (None, true) => Ok(Some(0)),
            (None, false) => Ok(None),
        }
    }
}

// ── Per-draft glue ──────────────────────────────────────────

/// Generates the conversion glue between one draft's standalone
/// `ObjectHeader` and the draft-neutral object types.
///
/// The leading keyword selects the draft's extension-block shape: absent
/// (draft-07), count-prefixed (draft-08), byte-length-prefixed (drafts
/// 09/10), or byte-length-prefixed and gated on the stream type (drafts
/// 11-13).
macro_rules! legacy_subgroup_glue {
    (no_extensions $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::conv;
            use super::{AnySubgroupObject, AnySubgroupObjectMeta};
            use crate::error::CodecError;
            use crate::$draft::data_stream::ObjectHeader;
            use crate::$draft::types::ObjectStatus;
            use bytes::{Buf, BufMut};

            pub fn read_object(buf: &mut impl Buf) -> Result<AnySubgroupObject, CodecError> {
                let header = ObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let (status, payload) = if payload_length == 0 {
                    (Some(header.object_status as u64), Vec::new())
                } else {
                    (None, conv::take(buf, payload_length)?)
                };
                Ok(AnySubgroupObject {
                    object_id: header.object_id.into_inner(),
                    extension_headers: Vec::new(),
                    extension_count: None,
                    status,
                    payload,
                })
            }

            pub fn read_object_meta(
                buf: &mut impl Buf,
            ) -> Result<AnySubgroupObjectMeta, CodecError> {
                let start = buf.remaining();
                let header = ObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let status = if payload_length == 0 {
                    Some(header.object_status as u64)
                } else {
                    conv::skip(buf, payload_length)?;
                    None
                };
                Ok(AnySubgroupObjectMeta {
                    object_id: header.object_id.into_inner(),
                    payload_length,
                    status,
                    extension_headers_len: 0,
                    wire_len: (start - buf.remaining()) as u64,
                })
            }

            pub fn write_object(
                object: &AnySubgroupObject,
                buf: &mut impl BufMut,
            ) -> Result<(), CodecError> {
                if !object.extension_headers.is_empty() {
                    return Err(CodecError::InvalidField);
                }
                let object_status = match conv::status_to_write(object)? {
                    Some(code) => ObjectStatus::from_u64(code).ok_or(CodecError::InvalidField)?,
                    None => ObjectStatus::Normal,
                };
                ObjectHeader {
                    object_id: conv::varint(object.object_id)?,
                    payload_length: conv::varint(object.payload.len() as u64)?,
                    object_status,
                }
                .encode(buf);
                buf.put_slice(&object.payload);
                Ok(())
            }
        }
    };

    (count_extensions $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::conv;
            use super::{AnySubgroupObject, AnySubgroupObjectMeta};
            use crate::error::CodecError;
            use crate::$draft::data_stream::ObjectHeader;
            use crate::$draft::types::ObjectStatus;
            use bytes::{Buf, BufMut};

            pub fn read_object(buf: &mut impl Buf) -> Result<AnySubgroupObject, CodecError> {
                let header = ObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let (status, payload) = if payload_length == 0 {
                    (Some(header.object_status as u64), Vec::new())
                } else {
                    (None, conv::take(buf, payload_length)?)
                };
                Ok(AnySubgroupObject {
                    object_id: header.object_id.into_inner(),
                    extension_headers: header.extensions,
                    extension_count: Some(header.extension_count.into_inner()),
                    status,
                    payload,
                })
            }

            pub fn read_object_meta(
                buf: &mut impl Buf,
            ) -> Result<AnySubgroupObjectMeta, CodecError> {
                let start = buf.remaining();
                let header = ObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let status = if payload_length == 0 {
                    Some(header.object_status as u64)
                } else {
                    conv::skip(buf, payload_length)?;
                    None
                };
                Ok(AnySubgroupObjectMeta {
                    object_id: header.object_id.into_inner(),
                    payload_length,
                    status,
                    extension_headers_len: header.extensions.len() as u64,
                    wire_len: (start - buf.remaining()) as u64,
                })
            }

            pub fn write_object(
                object: &AnySubgroupObject,
                buf: &mut impl BufMut,
            ) -> Result<(), CodecError> {
                let extension_count = match object.extension_count {
                    Some(count) => count,
                    None if object.extension_headers.is_empty() => 0,
                    None => return Err(CodecError::InvalidField),
                };
                let object_status = match conv::status_to_write(object)? {
                    Some(code) => ObjectStatus::from_u64(code).ok_or(CodecError::InvalidField)?,
                    None => ObjectStatus::Normal,
                };
                ObjectHeader {
                    object_id: conv::varint(object.object_id)?,
                    extension_count: conv::varint(extension_count)?,
                    extensions: object.extension_headers.clone(),
                    payload_length: conv::varint(object.payload.len() as u64)?,
                    object_status,
                }
                .encode(buf);
                buf.put_slice(&object.payload);
                Ok(())
            }
        }
    };

    (length_extensions $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::conv;
            use super::{AnySubgroupObject, AnySubgroupObjectMeta};
            use crate::error::CodecError;
            use crate::$draft::data_stream::ObjectHeader;
            use crate::$draft::types::ObjectStatus;
            use bytes::{Buf, BufMut};

            pub fn read_object(buf: &mut impl Buf) -> Result<AnySubgroupObject, CodecError> {
                let header = ObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let (status, payload) = if payload_length == 0 {
                    (Some(header.object_status as u64), Vec::new())
                } else {
                    (None, conv::take(buf, payload_length)?)
                };
                Ok(AnySubgroupObject {
                    object_id: header.object_id.into_inner(),
                    extension_headers: header.extensions,
                    extension_count: None,
                    status,
                    payload,
                })
            }

            pub fn read_object_meta(
                buf: &mut impl Buf,
            ) -> Result<AnySubgroupObjectMeta, CodecError> {
                let start = buf.remaining();
                let header = ObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let status = if payload_length == 0 {
                    Some(header.object_status as u64)
                } else {
                    conv::skip(buf, payload_length)?;
                    None
                };
                Ok(AnySubgroupObjectMeta {
                    object_id: header.object_id.into_inner(),
                    payload_length,
                    status,
                    extension_headers_len: header.extension_headers_length.into_inner(),
                    wire_len: (start - buf.remaining()) as u64,
                })
            }

            pub fn write_object(
                object: &AnySubgroupObject,
                buf: &mut impl BufMut,
            ) -> Result<(), CodecError> {
                let object_status = match conv::status_to_write(object)? {
                    Some(code) => ObjectStatus::from_u64(code).ok_or(CodecError::InvalidField)?,
                    None => ObjectStatus::Normal,
                };
                ObjectHeader {
                    object_id: conv::varint(object.object_id)?,
                    extension_headers_length: conv::varint(object.extension_headers.len() as u64)?,
                    extensions: object.extension_headers.clone(),
                    payload_length: conv::varint(object.payload.len() as u64)?,
                    object_status,
                }
                .encode(buf);
                buf.put_slice(&object.payload);
                Ok(())
            }
        }
    };

    (gated_extensions $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::conv;
            use super::{AnySubgroupObject, AnySubgroupObjectMeta};
            use crate::error::CodecError;
            use crate::$draft::data_stream::ObjectHeader;
            use crate::$draft::types::ObjectStatus;
            use bytes::{Buf, BufMut};

            pub fn read_object(
                extensions: bool,
                buf: &mut impl Buf,
            ) -> Result<AnySubgroupObject, CodecError> {
                let header = ObjectHeader::decode_with_extensions(extensions, buf)?;
                let payload_length = header.payload_length.into_inner();
                let (status, payload) = if payload_length == 0 {
                    (Some(header.object_status as u64), Vec::new())
                } else {
                    (None, conv::take(buf, payload_length)?)
                };
                Ok(AnySubgroupObject {
                    object_id: header.object_id.into_inner(),
                    extension_headers: header.extensions,
                    extension_count: None,
                    status,
                    payload,
                })
            }

            pub fn read_object_meta(
                extensions: bool,
                buf: &mut impl Buf,
            ) -> Result<AnySubgroupObjectMeta, CodecError> {
                let start = buf.remaining();
                let header = ObjectHeader::decode_with_extensions(extensions, buf)?;
                let payload_length = header.payload_length.into_inner();
                let status = if payload_length == 0 {
                    Some(header.object_status as u64)
                } else {
                    conv::skip(buf, payload_length)?;
                    None
                };
                Ok(AnySubgroupObjectMeta {
                    object_id: header.object_id.into_inner(),
                    payload_length,
                    status,
                    extension_headers_len: header.extension_headers_length.into_inner(),
                    wire_len: (start - buf.remaining()) as u64,
                })
            }

            pub fn write_object(
                extensions: bool,
                object: &AnySubgroupObject,
                buf: &mut impl BufMut,
            ) -> Result<(), CodecError> {
                if !extensions && !object.extension_headers.is_empty() {
                    return Err(CodecError::InvalidField);
                }
                let object_status = match conv::status_to_write(object)? {
                    Some(code) => ObjectStatus::from_u64(code).ok_or(CodecError::InvalidField)?,
                    None => ObjectStatus::Normal,
                };
                ObjectHeader {
                    object_id: conv::varint(object.object_id)?,
                    extension_headers_length: conv::varint(object.extension_headers.len() as u64)?,
                    extensions: object.extension_headers.clone(),
                    payload_length: conv::varint(object.payload.len() as u64)?,
                    object_status,
                }
                .encode_with_extensions(extensions, buf);
                buf.put_slice(&object.payload);
                Ok(())
            }
        }
    };
}

legacy_subgroup_glue!(no_extensions sg07, "draft07", draft07);
legacy_subgroup_glue!(count_extensions sg08, "draft08", draft08);
legacy_subgroup_glue!(length_extensions sg09, "draft09", draft09);
legacy_subgroup_glue!(length_extensions sg10, "draft10", draft10);
legacy_subgroup_glue!(gated_extensions sg11, "draft11", draft11);
legacy_subgroup_glue!(gated_extensions sg12, "draft12", draft12);
legacy_subgroup_glue!(gated_extensions sg13, "draft13", draft13);

/// Generates the conversion glue between one draft's stateful
/// `SubgroupObjectReader` and the draft-neutral object types.
///
/// Every draft from 14 on carries a typed `ObjectStatus`, so the leading
/// keyword selects how the payload length reaches the wire instead: draft-14
/// derives it from the payload, while drafts 15-21 carry an explicit
/// payload-length field, which this glue always sets from the payload.
///
/// Both arms funnel the draft-neutral `AnySubgroupObject`, whose status is a
/// bare `u64`, through the target draft's `ObjectStatus::from_u64`. That is
/// the one place a status code the target draft does not assign can still be
/// offered to an encoder at run time — relaying an object between drafts, for
/// instance — and it is refused there with `CodecError::InvalidField`.
macro_rules! modern_subgroup_glue {
    (derived_length $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::conv;
            use super::{AnySubgroupObject, AnySubgroupObjectMeta};
            use crate::error::CodecError;
            use crate::$draft::data_stream::{SubgroupObject, SubgroupObjectReader};
            use crate::$draft::types::ObjectStatus;
            use bytes::{Buf, BufMut};

            pub fn read_object(
                reader: &mut SubgroupObjectReader,
                buf: &mut impl Buf,
            ) -> Result<AnySubgroupObject, CodecError> {
                let object = reader.read_object(buf)?;
                Ok(AnySubgroupObject {
                    object_id: object.object_id.into_inner(),
                    extension_headers: object.extension_headers,
                    extension_count: None,
                    status: object.status.map(ObjectStatus::as_u64),
                    payload: object.payload,
                })
            }

            pub fn read_object_meta(
                reader: &mut SubgroupObjectReader,
                buf: &mut impl Buf,
            ) -> Result<AnySubgroupObjectMeta, CodecError> {
                let meta = reader.read_object_meta(buf)?;
                Ok(AnySubgroupObjectMeta {
                    object_id: meta.object_id,
                    payload_length: meta.payload_length,
                    status: meta.status,
                    extension_headers_len: meta.extension_headers_len,
                    wire_len: meta.wire_len,
                })
            }

            pub fn write_object(
                writer: &mut SubgroupObjectReader,
                object: &AnySubgroupObject,
                buf: &mut impl BufMut,
            ) -> Result<(), CodecError> {
                let status = match conv::status_to_write(object)? {
                    Some(code) => {
                        Some(ObjectStatus::from_u64(code).ok_or(CodecError::InvalidField)?)
                    }
                    None => None,
                };
                writer.write_object(
                    &SubgroupObject {
                        object_id: conv::varint(object.object_id)?,
                        extension_headers: object.extension_headers.clone(),
                        status,
                        payload: object.payload.clone(),
                    },
                    buf,
                )
            }
        }
    };

    (explicit_length $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::conv;
            use super::{AnySubgroupObject, AnySubgroupObjectMeta};
            use crate::error::CodecError;
            use crate::$draft::data_stream::{SubgroupObject, SubgroupObjectReader};
            use crate::$draft::types::ObjectStatus;
            use bytes::{Buf, BufMut};

            pub fn read_object(
                reader: &mut SubgroupObjectReader,
                buf: &mut impl Buf,
            ) -> Result<AnySubgroupObject, CodecError> {
                let object = reader.read_object(buf)?;
                Ok(AnySubgroupObject {
                    object_id: object.object_id.into_inner(),
                    extension_headers: object.extension_headers,
                    extension_count: None,
                    status: object.object_status.map(ObjectStatus::as_u64),
                    payload: object.payload,
                })
            }

            pub fn read_object_meta(
                reader: &mut SubgroupObjectReader,
                buf: &mut impl Buf,
            ) -> Result<AnySubgroupObjectMeta, CodecError> {
                let meta = reader.read_object_meta(buf)?;
                Ok(AnySubgroupObjectMeta {
                    object_id: meta.object_id,
                    payload_length: meta.payload_length,
                    status: meta.status,
                    extension_headers_len: meta.extension_headers_len,
                    wire_len: meta.wire_len,
                })
            }

            pub fn write_object(
                writer: &mut SubgroupObjectReader,
                object: &AnySubgroupObject,
                buf: &mut impl BufMut,
            ) -> Result<(), CodecError> {
                let object_status = match conv::status_to_write(object)? {
                    Some(code) => {
                        Some(ObjectStatus::from_u64(code).ok_or(CodecError::InvalidField)?)
                    }
                    None => None,
                };
                writer.write_object(
                    &SubgroupObject {
                        object_id: conv::varint(object.object_id)?,
                        extension_headers: object.extension_headers.clone(),
                        payload_length: conv::varint(object.payload.len() as u64)?,
                        object_status,
                        payload: object.payload.clone(),
                    },
                    buf,
                )
            }
        }
    };
}

modern_subgroup_glue!(derived_length sg14, "draft14", draft14);
modern_subgroup_glue!(explicit_length sg15, "draft15", draft15);
modern_subgroup_glue!(explicit_length sg16, "draft16", draft16);
modern_subgroup_glue!(explicit_length sg17, "draft17", draft17);
modern_subgroup_glue!(explicit_length sg18, "draft18", draft18);
modern_subgroup_glue!(explicit_length sg19, "draft19", draft19);
modern_subgroup_glue!(explicit_length sg20, "draft20", draft20);
modern_subgroup_glue!(explicit_length sg21, "draft21", draft21);

/// Generates the conversion glue for one draft's fetch objects.
///
/// The leading keyword selects the extension-block shape, as for
/// `legacy_subgroup_glue!`. Unlike subgroup objects, the fetch extension
/// block is unconditional on drafts 09-13 — it is never gated on the stream
/// type.
macro_rules! fetch_glue {
    (no_extensions $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::conv;
            use super::{AnyFetchObject, AnyFetchObjectMeta};
            use crate::error::CodecError;
            use crate::$draft::data_stream::FetchObjectHeader;
            use bytes::Buf;

            pub fn read_object(buf: &mut impl Buf) -> Result<AnyFetchObject, CodecError> {
                let header = FetchObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let (status, payload) = if payload_length == 0 {
                    (Some(header.object_status as u64), Vec::new())
                } else {
                    (None, conv::take(buf, payload_length)?)
                };
                Ok(AnyFetchObject {
                    group_id: header.group_id.into_inner(),
                    subgroup_id: header.subgroup_id.into_inner(),
                    has_subgroup_id: true,
                    object_id: header.object_id.into_inner(),
                    publisher_priority: header.publisher_priority,
                    extension_headers: Vec::new(),
                    extension_count: None,
                    status,
                    end_of_range: None,
                    payload,
                })
            }

            pub fn read_object_meta(buf: &mut impl Buf) -> Result<AnyFetchObjectMeta, CodecError> {
                let start = buf.remaining();
                let header = FetchObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let status = if payload_length == 0 {
                    Some(header.object_status as u64)
                } else {
                    conv::skip(buf, payload_length)?;
                    None
                };
                Ok(AnyFetchObjectMeta {
                    group_id: header.group_id.into_inner(),
                    subgroup_id: header.subgroup_id.into_inner(),
                    has_subgroup_id: true,
                    object_id: header.object_id.into_inner(),
                    publisher_priority: header.publisher_priority,
                    payload_length,
                    status,
                    end_of_range: None,
                    extension_headers_len: 0,
                    wire_len: (start - buf.remaining()) as u64,
                })
            }
        }
    };

    (count_extensions $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::conv;
            use super::{AnyFetchObject, AnyFetchObjectMeta};
            use crate::error::CodecError;
            use crate::$draft::data_stream::FetchObjectHeader;
            use bytes::Buf;

            pub fn read_object(buf: &mut impl Buf) -> Result<AnyFetchObject, CodecError> {
                let header = FetchObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let (status, payload) = if payload_length == 0 {
                    (Some(header.object_status as u64), Vec::new())
                } else {
                    (None, conv::take(buf, payload_length)?)
                };
                Ok(AnyFetchObject {
                    group_id: header.group_id.into_inner(),
                    subgroup_id: header.subgroup_id.into_inner(),
                    has_subgroup_id: true,
                    object_id: header.object_id.into_inner(),
                    publisher_priority: header.publisher_priority,
                    extension_headers: header.extensions,
                    extension_count: Some(header.extension_count.into_inner()),
                    status,
                    end_of_range: None,
                    payload,
                })
            }

            pub fn read_object_meta(buf: &mut impl Buf) -> Result<AnyFetchObjectMeta, CodecError> {
                let start = buf.remaining();
                let header = FetchObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let status = if payload_length == 0 {
                    Some(header.object_status as u64)
                } else {
                    conv::skip(buf, payload_length)?;
                    None
                };
                Ok(AnyFetchObjectMeta {
                    group_id: header.group_id.into_inner(),
                    subgroup_id: header.subgroup_id.into_inner(),
                    has_subgroup_id: true,
                    object_id: header.object_id.into_inner(),
                    publisher_priority: header.publisher_priority,
                    payload_length,
                    status,
                    end_of_range: None,
                    extension_headers_len: header.extensions.len() as u64,
                    wire_len: (start - buf.remaining()) as u64,
                })
            }
        }
    };

    (length_extensions $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::conv;
            use super::{AnyFetchObject, AnyFetchObjectMeta};
            use crate::error::CodecError;
            use crate::$draft::data_stream::FetchObjectHeader;
            use bytes::Buf;

            pub fn read_object(buf: &mut impl Buf) -> Result<AnyFetchObject, CodecError> {
                let header = FetchObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let (status, payload) = if payload_length == 0 {
                    (Some(header.object_status as u64), Vec::new())
                } else {
                    (None, conv::take(buf, payload_length)?)
                };
                Ok(AnyFetchObject {
                    group_id: header.group_id.into_inner(),
                    subgroup_id: header.subgroup_id.into_inner(),
                    has_subgroup_id: true,
                    object_id: header.object_id.into_inner(),
                    publisher_priority: header.publisher_priority,
                    extension_headers: header.extensions,
                    extension_count: None,
                    status,
                    end_of_range: None,
                    payload,
                })
            }

            pub fn read_object_meta(buf: &mut impl Buf) -> Result<AnyFetchObjectMeta, CodecError> {
                let start = buf.remaining();
                let header = FetchObjectHeader::decode(buf)?;
                let payload_length = header.payload_length.into_inner();
                let status = if payload_length == 0 {
                    Some(header.object_status as u64)
                } else {
                    conv::skip(buf, payload_length)?;
                    None
                };
                Ok(AnyFetchObjectMeta {
                    group_id: header.group_id.into_inner(),
                    subgroup_id: header.subgroup_id.into_inner(),
                    has_subgroup_id: true,
                    object_id: header.object_id.into_inner(),
                    publisher_priority: header.publisher_priority,
                    payload_length,
                    status,
                    end_of_range: None,
                    extension_headers_len: header.extension_headers_length.into_inner(),
                    wire_len: (start - buf.remaining()) as u64,
                })
            }
        }
    };
}

fetch_glue!(no_extensions fo07, "draft07", draft07);
fetch_glue!(count_extensions fo08, "draft08", draft08);
fetch_glue!(length_extensions fo09, "draft09", draft09);
fetch_glue!(length_extensions fo10, "draft10", draft10);
fetch_glue!(length_extensions fo11, "draft11", draft11);
fetch_glue!(length_extensions fo12, "draft12", draft12);
fetch_glue!(length_extensions fo13, "draft13", draft13);

#[cfg(feature = "draft14")]
mod fo14 {
    use super::{AnyFetchObject, AnyFetchObjectMeta};
    use crate::draft14::data_stream::FetchObject;
    use crate::draft14::types::ObjectStatus;
    use crate::error::CodecError;
    use bytes::Buf;

    pub fn read_object(buf: &mut impl Buf) -> Result<AnyFetchObject, CodecError> {
        let object = FetchObject::decode(buf)?;
        Ok(AnyFetchObject {
            group_id: object.group_id.into_inner(),
            subgroup_id: object.subgroup_id.into_inner(),
            has_subgroup_id: true,
            object_id: object.object_id.into_inner(),
            publisher_priority: object.publisher_priority,
            extension_headers: object.extension_headers,
            extension_count: None,
            status: object.status.map(ObjectStatus::as_u64),
            end_of_range: None,
            payload: object.payload,
        })
    }

    pub fn read_object_meta(buf: &mut impl Buf) -> Result<AnyFetchObjectMeta, CodecError> {
        let meta = FetchObject::decode_meta(buf)?;
        Ok(AnyFetchObjectMeta {
            group_id: meta.group_id,
            subgroup_id: meta.subgroup_id,
            has_subgroup_id: true,
            object_id: meta.object_id,
            publisher_priority: meta.publisher_priority,
            payload_length: meta.payload_length,
            status: meta.status,
            end_of_range: None,
            extension_headers_len: meta.extension_headers_len,
            wire_len: meta.wire_len,
        })
    }
}

#[cfg(feature = "draft15")]
mod fo15 {
    use super::{conv, AnyFetchObject, AnyFetchObjectMeta};
    use crate::draft15::data_stream::FetchObjectReader;
    use crate::draft15::types::ObjectStatus;
    use crate::error::CodecError;
    use bytes::Buf;

    pub fn read_object(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObject, CodecError> {
        let header = reader.read_object_header(buf)?;
        // The draft-15 reader stops at the payload length so a caller can
        // forward the bytes without copying them; the draft-neutral object
        // holds the payload, so the copy happens here instead.
        let payload = conv::take(buf, header.payload_length.into_inner())?;
        Ok(AnyFetchObject {
            group_id: header.group_id.into_inner(),
            subgroup_id: header.subgroup_id.into_inner(),
            has_subgroup_id: true,
            object_id: header.object_id.into_inner(),
            publisher_priority: header.publisher_priority,
            extension_headers: header.extension_headers,
            extension_count: None,
            // Already `Some` only for a zero-length object, which is the
            // draft-neutral convention too.
            status: header.object_status.map(ObjectStatus::as_u64),
            end_of_range: None,
            payload,
        })
    }

    pub fn read_object_frame(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<super::AnyFetchFrame, CodecError> {
        let start = buf.remaining();
        let header = reader.read_object_header(buf)?;
        let payload_length = header.payload_length.into_inner();
        conv::skip(buf, payload_length)?;
        let meta = AnyFetchObjectMeta {
            group_id: header.group_id.into_inner(),
            subgroup_id: header.subgroup_id.into_inner(),
            has_subgroup_id: true,
            object_id: header.object_id.into_inner(),
            publisher_priority: header.publisher_priority,
            payload_length,
            status: header.object_status.map(ObjectStatus::as_u64),
            end_of_range: None,
            extension_headers_len: header.extension_headers.len() as u64,
            wire_len: (start - buf.remaining()) as u64,
        };
        Ok(super::AnyFetchFrame {
            meta,
            draft: crate::version::DraftVersion::Draft15,
            shape: super::FetchFrameShape::Draft15(header),
        })
    }

    pub fn read_object_meta(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObjectMeta, CodecError> {
        read_object_frame(reader, buf).map(|frame| frame.meta)
    }
}

#[cfg(feature = "draft16")]
mod fo16 {
    use super::DEFAULT_PUBLISHER_PRIORITY;
    use super::{conv, AnyFetchEndOfRange, AnyFetchObject, AnyFetchObjectMeta};
    use crate::draft16::data_stream::{
        FetchEndOfRange, FetchObjectHeader, FetchObjectLocation, FetchObjectReader,
    };
    use crate::error::CodecError;
    use bytes::Buf;

    /// Draft-16 keeps the frame and its resolved Location apart, and both are
    /// carried out of here: the Location fills the draft-neutral value, and the
    /// pair of them is what re-encoding this frame later takes.
    fn parts(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<(FetchObjectHeader, FetchObjectLocation), CodecError> {
        let header = FetchObjectHeader::decode(buf)?;
        let location = reader.resolve(&header)?;
        Ok((header, location))
    }

    fn resolved(location: &FetchObjectLocation) -> super::Resolved {
        let end_of_range = location.end_of_range;
        super::Resolved {
            group_id: location.group_id,
            // Draft-16 Section 10.4.4.2 gives an End of Range indicator a Group
            // ID and an Object ID and says "Subgroup ID, Priority and Extensions
            // are not present". Its per-draft resolver still reads the two low
            // flag bits of a marker as Subgroup ID mode zero and answers zero,
            // which is a real Subgroup ID; the draft-neutral value says the
            // marker has none, as drafts 17-21 do.
            subgroup_id: location.subgroup_id.filter(|_| end_of_range.is_none()),
            object_id: location.object_id,
            publisher_priority: location.publisher_priority.unwrap_or(DEFAULT_PUBLISHER_PRIORITY),
            end_of_range: end_of_range.map(|r| match r {
                FetchEndOfRange::NonExistent => AnyFetchEndOfRange::NonExistent,
                FetchEndOfRange::Unknown => AnyFetchEndOfRange::Unknown,
            }),
        }
    }

    pub fn read_object(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObject, CodecError> {
        let (header, location) = parts(reader, buf)?;
        let payload = conv::take(buf, header.payload_length.into_inner())?;
        Ok(resolved(&location).into_object(header.extensions.unwrap_or_default(), payload))
    }

    pub fn read_object_frame(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<super::AnyFetchFrame, CodecError> {
        let start = buf.remaining();
        let (header, location) = parts(reader, buf)?;
        let payload_length = header.payload_length.into_inner();
        conv::skip(buf, payload_length)?;
        let meta = resolved(&location).into_meta(
            header.extensions.as_ref().map_or(0, |e| e.len() as u64),
            payload_length,
            (start - buf.remaining()) as u64,
        );
        Ok(super::AnyFetchFrame {
            meta,
            draft: crate::version::DraftVersion::Draft16,
            shape: super::FetchFrameShape::Draft16(header, location),
        })
    }

    pub fn read_object_meta(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObjectMeta, CodecError> {
        read_object_frame(reader, buf).map(|frame| frame.meta)
    }
}

#[cfg(feature = "draft17")]
mod fo17 {
    use super::{conv, AnyFetchEndOfRange, AnyFetchObject, AnyFetchObjectMeta};
    use crate::draft17::data_stream::{EndOfRange, FetchObject, FetchObjectReader};
    use crate::error::CodecError;
    use bytes::Buf;

    fn resolved(object: &FetchObject) -> super::Resolved {
        super::Resolved {
            group_id: object.group_id,
            subgroup_id: object.subgroup_id,
            object_id: object.object_id,
            publisher_priority: object
                .publisher_priority
                .unwrap_or(super::DEFAULT_PUBLISHER_PRIORITY),
            end_of_range: object.header.end_of_range().map(|r| match r {
                EndOfRange::NonExistent => AnyFetchEndOfRange::NonExistent,
                EndOfRange::Unknown => AnyFetchEndOfRange::Unknown,
            }),
        }
    }

    pub fn read_object(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObject, CodecError> {
        let object = reader.read_object_header(buf)?;
        let resolved = resolved(&object);
        let payload = conv::take(buf, object.header.payload_length.into_inner())?;
        Ok(resolved.into_object(object.header.properties, payload))
    }

    pub fn read_object_frame(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<super::AnyFetchFrame, CodecError> {
        let start = buf.remaining();
        let object = reader.read_object_header(buf)?;
        let resolved = resolved(&object);
        let payload_length = object.header.payload_length.into_inner();
        conv::skip(buf, payload_length)?;
        let meta = resolved.into_meta(
            object.header.properties.len() as u64,
            payload_length,
            (start - buf.remaining()) as u64,
        );
        Ok(super::AnyFetchFrame {
            meta,
            draft: crate::version::DraftVersion::Draft17,
            shape: super::FetchFrameShape::Draft17(object),
        })
    }

    pub fn read_object_meta(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObjectMeta, CodecError> {
        read_object_frame(reader, buf).map(|frame| frame.meta)
    }
}

#[cfg(feature = "draft18")]
mod fo18 {
    use super::{conv, AnyFetchEndOfRange, AnyFetchObject, AnyFetchObjectMeta};
    use crate::draft18::data_stream::{EndOfRange, FetchObject, FetchObjectReader};
    use crate::error::CodecError;
    use bytes::Buf;

    fn resolved(object: &FetchObject) -> super::Resolved {
        super::Resolved {
            group_id: object.group_id,
            subgroup_id: object.subgroup_id,
            object_id: object.object_id,
            publisher_priority: object
                .publisher_priority
                .unwrap_or(super::DEFAULT_PUBLISHER_PRIORITY),
            end_of_range: object.header.end_of_range().map(|r| match r {
                EndOfRange::NonExistent => AnyFetchEndOfRange::NonExistent,
                EndOfRange::Unknown => AnyFetchEndOfRange::Unknown,
            }),
        }
    }

    pub fn read_object(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObject, CodecError> {
        let object = reader.read_object_header(buf)?;
        let resolved = resolved(&object);
        let payload = conv::take(buf, object.header.payload_length.into_inner())?;
        Ok(resolved.into_object(object.header.properties, payload))
    }

    pub fn read_object_frame(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<super::AnyFetchFrame, CodecError> {
        let start = buf.remaining();
        let object = reader.read_object_header(buf)?;
        let resolved = resolved(&object);
        let payload_length = object.header.payload_length.into_inner();
        conv::skip(buf, payload_length)?;
        let meta = resolved.into_meta(
            object.header.properties.len() as u64,
            payload_length,
            (start - buf.remaining()) as u64,
        );
        Ok(super::AnyFetchFrame {
            meta,
            draft: crate::version::DraftVersion::Draft18,
            shape: super::FetchFrameShape::Draft18(object),
        })
    }

    pub fn read_object_meta(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObjectMeta, CodecError> {
        read_object_frame(reader, buf).map(|frame| frame.meta)
    }
}

#[cfg(feature = "draft19")]
mod fo19 {
    use super::{conv, AnyFetchEndOfRange, AnyFetchObject, AnyFetchObjectMeta};
    use crate::draft19::data_stream::{FetchEndOfRange, FetchObject, FetchObjectReader};
    use crate::error::CodecError;
    use bytes::Buf;

    fn resolved(object: &FetchObject) -> super::Resolved {
        super::Resolved {
            group_id: object.group_id,
            subgroup_id: object.subgroup_id,
            object_id: object.object_id,
            publisher_priority: object
                .publisher_priority
                .unwrap_or(super::DEFAULT_PUBLISHER_PRIORITY),
            end_of_range: object.header.end_of_range().map(|r| match r {
                FetchEndOfRange::NonExistent => AnyFetchEndOfRange::NonExistent,
                FetchEndOfRange::Unknown => AnyFetchEndOfRange::Unknown,
            }),
        }
    }

    pub fn read_object(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObject, CodecError> {
        let object = reader.read_object_header(buf)?;
        let resolved = resolved(&object);
        let payload = conv::take(buf, object.header.payload_length.into_inner())?;
        Ok(resolved.into_object(object.header.properties.unwrap_or_default(), payload))
    }

    pub fn read_object_frame(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<super::AnyFetchFrame, CodecError> {
        let start = buf.remaining();
        let object = reader.read_object_header(buf)?;
        let resolved = resolved(&object);
        let payload_length = object.header.payload_length.into_inner();
        conv::skip(buf, payload_length)?;
        let meta = resolved.into_meta(
            object.header.properties.as_ref().map_or(0, |p| p.len() as u64),
            payload_length,
            (start - buf.remaining()) as u64,
        );
        Ok(super::AnyFetchFrame {
            meta,
            draft: crate::version::DraftVersion::Draft19,
            shape: super::FetchFrameShape::Draft19(object),
        })
    }

    pub fn read_object_meta(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObjectMeta, CodecError> {
        read_object_frame(reader, buf).map(|frame| frame.meta)
    }
}

#[cfg(feature = "draft20")]
mod fo20 {
    use super::{conv, AnyFetchEndOfRange, AnyFetchObject, AnyFetchObjectMeta};
    use crate::draft20::data_stream::{FetchEndOfRange, FetchObject, FetchObjectReader};
    use crate::error::CodecError;
    use bytes::Buf;

    fn resolved(object: &FetchObject) -> super::Resolved {
        super::Resolved {
            group_id: object.group_id,
            subgroup_id: object.subgroup_id,
            object_id: object.object_id,
            publisher_priority: object
                .publisher_priority
                .unwrap_or(super::DEFAULT_PUBLISHER_PRIORITY),
            end_of_range: object.header.end_of_range().map(|r| match r {
                FetchEndOfRange::NonExistent => AnyFetchEndOfRange::NonExistent,
                FetchEndOfRange::Unknown => AnyFetchEndOfRange::Unknown,
                // Draft-20's third marker, Table 7's 0x20C. Only this draft's
                // arm can produce it.
                FetchEndOfRange::TimedOut => AnyFetchEndOfRange::TimedOut,
            }),
        }
    }

    pub fn read_object(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObject, CodecError> {
        let object = reader.read_object_header(buf)?;
        let resolved = resolved(&object);
        let payload = conv::take(buf, object.header.payload_length.into_inner())?;
        Ok(resolved.into_object(object.header.properties.unwrap_or_default(), payload))
    }

    pub fn read_object_frame(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<super::AnyFetchFrame, CodecError> {
        let start = buf.remaining();
        let object = reader.read_object_header(buf)?;
        let resolved = resolved(&object);
        let payload_length = object.header.payload_length.into_inner();
        conv::skip(buf, payload_length)?;
        let meta = resolved.into_meta(
            object.header.properties.as_ref().map_or(0, |p| p.len() as u64),
            payload_length,
            (start - buf.remaining()) as u64,
        );
        Ok(super::AnyFetchFrame {
            meta,
            draft: crate::version::DraftVersion::Draft20,
            shape: super::FetchFrameShape::Draft20(object),
        })
    }

    pub fn read_object_meta(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObjectMeta, CodecError> {
        read_object_frame(reader, buf).map(|frame| frame.meta)
    }
}
#[cfg(feature = "draft21")]
mod fo21 {
    use super::{conv, AnyFetchEndOfRange, AnyFetchObject, AnyFetchObjectMeta};
    use crate::draft21::data_stream::{FetchEndOfRange, FetchObject, FetchObjectReader};
    use crate::error::CodecError;
    use bytes::Buf;

    fn resolved(object: &FetchObject) -> super::Resolved {
        super::Resolved {
            group_id: object.group_id,
            subgroup_id: object.subgroup_id,
            object_id: object.object_id,
            publisher_priority: object
                .publisher_priority
                .unwrap_or(super::DEFAULT_PUBLISHER_PRIORITY),
            end_of_range: object.header.end_of_range().map(|r| match r {
                FetchEndOfRange::NonExistent => AnyFetchEndOfRange::NonExistent,
                FetchEndOfRange::Unknown => AnyFetchEndOfRange::Unknown,
                // Draft-21's third marker, Table 7's 0x20C. Only this draft's
                // arm can produce it.
                FetchEndOfRange::TimedOut => AnyFetchEndOfRange::TimedOut,
            }),
        }
    }

    pub fn read_object(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObject, CodecError> {
        let object = reader.read_object_header(buf)?;
        let resolved = resolved(&object);
        let payload = conv::take(buf, object.header.payload_length.into_inner())?;
        Ok(resolved.into_object(object.header.properties.unwrap_or_default(), payload))
    }

    pub fn read_object_frame(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<super::AnyFetchFrame, CodecError> {
        let start = buf.remaining();
        let object = reader.read_object_header(buf)?;
        let resolved = resolved(&object);
        let payload_length = object.header.payload_length.into_inner();
        conv::skip(buf, payload_length)?;
        let meta = resolved.into_meta(
            object.header.properties.as_ref().map_or(0, |p| p.len() as u64),
            payload_length,
            (start - buf.remaining()) as u64,
        );
        Ok(super::AnyFetchFrame {
            meta,
            draft: crate::version::DraftVersion::Draft21,
            shape: super::FetchFrameShape::Draft21(object),
        })
    }

    pub fn read_object_meta(
        reader: &mut FetchObjectReader,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObjectMeta, CodecError> {
        read_object_frame(reader, buf).map(|frame| frame.meta)
    }
}

/// A drafts-16-to-19 fetch frame's identity once the fields its Serialization
/// Flags left off the wire have been filled in.
///
/// The four drafts read those flags differently enough to need a resolver
/// each, but they all end up saying the same five things, and turning that into
/// a draft-neutral value is the same work every time. `subgroup_id` is `None`
/// for the frames that have none at all rather than zero, which is a real
/// Subgroup ID; see [`AnyFetchObject::has_subgroup_id`].
#[cfg(any(
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
struct Resolved {
    group_id: u64,
    subgroup_id: Option<u64>,
    object_id: u64,
    publisher_priority: u8,
    end_of_range: Option<AnyFetchEndOfRange>,
}

#[cfg(any(
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
impl Resolved {
    fn into_object(self, extension_headers: Vec<u8>, payload: Vec<u8>) -> AnyFetchObject {
        AnyFetchObject {
            group_id: self.group_id,
            subgroup_id: self.subgroup_id.unwrap_or(0),
            has_subgroup_id: self.subgroup_id.is_some(),
            object_id: self.object_id,
            publisher_priority: self.publisher_priority,
            extension_headers,
            extension_count: None,
            // Drafts 16-21 removed the Object Status field from fetch objects;
            // a zero-length payload here carries no code to report.
            status: None,
            end_of_range: self.end_of_range,
            payload,
        }
    }

    fn into_meta(
        self,
        extension_headers_len: u64,
        payload_length: u64,
        wire_len: u64,
    ) -> AnyFetchObjectMeta {
        AnyFetchObjectMeta {
            group_id: self.group_id,
            subgroup_id: self.subgroup_id.unwrap_or(0),
            has_subgroup_id: self.subgroup_id.is_some(),
            object_id: self.object_id,
            publisher_priority: self.publisher_priority,
            payload_length,
            status: None,
            end_of_range: self.end_of_range,
            extension_headers_len,
            wire_len,
        }
    }
}

// ── Subgroup object reader ──────────────────────────────────

/// Per-draft reader state. Drafts 07-10 need none, drafts 11-13 need the
/// stream type's extensions-present flag, drafts 14-21 own a stateful
/// per-draft reader that tracks the Object ID delta.
#[derive(Debug, Clone)]
enum SubgroupReaderState {
    #[cfg(feature = "draft07")]
    Draft07,
    #[cfg(feature = "draft08")]
    Draft08,
    #[cfg(feature = "draft09")]
    Draft09,
    #[cfg(feature = "draft10")]
    Draft10,
    #[cfg(feature = "draft11")]
    Draft11 { extensions: bool },
    #[cfg(feature = "draft12")]
    Draft12 { extensions: bool },
    #[cfg(feature = "draft13")]
    Draft13 { extensions: bool },
    #[cfg(feature = "draft14")]
    Draft14(crate::draft14::data_stream::SubgroupObjectReader),
    #[cfg(feature = "draft15")]
    Draft15(crate::draft15::data_stream::SubgroupObjectReader),
    #[cfg(feature = "draft16")]
    Draft16(crate::draft16::data_stream::SubgroupObjectReader),
    #[cfg(feature = "draft17")]
    Draft17(crate::draft17::data_stream::SubgroupObjectReader),
    #[cfg(feature = "draft18")]
    Draft18(crate::draft18::data_stream::SubgroupObjectReader),
    #[cfg(feature = "draft19")]
    Draft19(crate::draft19::data_stream::SubgroupObjectReader),
    #[cfg(feature = "draft20")]
    Draft20(crate::draft20::data_stream::SubgroupObjectReader),
    #[cfg(feature = "draft21")]
    Draft21(crate::draft21::data_stream::SubgroupObjectReader),
}

/// Stateful reader for the objects on a subgroup data stream, for any
/// enabled draft.
///
/// Drafts 07-13 encode absolute object IDs and need no state, drafts 14-21
/// delta-encode them against the previous object. This reader presents both
/// as the same API: construct it from the stream's header, then call
/// [`read_object`](Self::read_object) once per object.
///
/// The reader is [`Clone`] specifically so callers can probe a partial buffer
/// against a copy and commit only on success; see the module docs.
#[derive(Debug, Clone)]
pub struct AnySubgroupObjectReader {
    state: SubgroupReaderState,
}

impl AnySubgroupObjectReader {
    /// Create a reader seeded from the stream's subgroup header.
    ///
    /// Returns [`CodecError::UnsupportedDraft`] when the header's draft is
    /// not compiled in, and [`CodecError::InvalidField`] when the header's
    /// stream type is not a subgroup type.
    #[allow(unused_variables, unreachable_code)]
    pub fn new(header: &AnySubgroupHeader) -> Result<Self, CodecError> {
        let state = match header {
            #[cfg(feature = "draft07")]
            AnySubgroupHeader::Draft07(_) => SubgroupReaderState::Draft07,
            #[cfg(feature = "draft08")]
            AnySubgroupHeader::Draft08(_) => SubgroupReaderState::Draft08,
            #[cfg(feature = "draft09")]
            AnySubgroupHeader::Draft09(_) => SubgroupReaderState::Draft09,
            #[cfg(feature = "draft10")]
            AnySubgroupHeader::Draft10(_) => SubgroupReaderState::Draft10,
            #[cfg(feature = "draft11")]
            AnySubgroupHeader::Draft11(h) => {
                SubgroupReaderState::Draft11 { extensions: subgroup_extensions_11(h)? }
            }
            #[cfg(feature = "draft12")]
            AnySubgroupHeader::Draft12(h) => {
                SubgroupReaderState::Draft12 { extensions: subgroup_extensions_12(h)? }
            }
            #[cfg(feature = "draft13")]
            AnySubgroupHeader::Draft13(h) => {
                SubgroupReaderState::Draft13 { extensions: subgroup_extensions_13(h)? }
            }
            #[cfg(feature = "draft14")]
            AnySubgroupHeader::Draft14(h) => SubgroupReaderState::Draft14(
                crate::draft14::data_stream::SubgroupObjectReader::new(h),
            ),
            #[cfg(feature = "draft15")]
            AnySubgroupHeader::Draft15(h) => SubgroupReaderState::Draft15(
                crate::draft15::data_stream::SubgroupObjectReader::new(h),
            ),
            #[cfg(feature = "draft16")]
            AnySubgroupHeader::Draft16(h) => SubgroupReaderState::Draft16(
                crate::draft16::data_stream::SubgroupObjectReader::new(h),
            ),
            #[cfg(feature = "draft17")]
            AnySubgroupHeader::Draft17(h) => SubgroupReaderState::Draft17(
                crate::draft17::data_stream::SubgroupObjectReader::new(h),
            ),
            #[cfg(feature = "draft18")]
            AnySubgroupHeader::Draft18(h) => SubgroupReaderState::Draft18(
                crate::draft18::data_stream::SubgroupObjectReader::new(h),
            ),
            #[cfg(feature = "draft19")]
            AnySubgroupHeader::Draft19(h) => SubgroupReaderState::Draft19(
                crate::draft19::data_stream::SubgroupObjectReader::new(h),
            ),
            #[cfg(feature = "draft20")]
            AnySubgroupHeader::Draft20(h) => SubgroupReaderState::Draft20(
                crate::draft20::data_stream::SubgroupObjectReader::new(h),
            ),
            #[cfg(feature = "draft21")]
            AnySubgroupHeader::Draft21(h) => SubgroupReaderState::Draft21(
                crate::draft21::data_stream::SubgroupObjectReader::new(h),
            ),
            #[allow(unreachable_patterns)]
            _ => {
                return Err(CodecError::UnsupportedDraft(format!(
                    "draft {:?} not enabled via feature flag",
                    header.draft()
                )));
            }
        };
        Ok(Self { state })
    }

    /// The draft this reader decodes.
    #[allow(unreachable_code)]
    pub fn draft(&self) -> DraftVersion {
        match &self.state {
            #[cfg(feature = "draft07")]
            SubgroupReaderState::Draft07 => DraftVersion::Draft07,
            #[cfg(feature = "draft08")]
            SubgroupReaderState::Draft08 => DraftVersion::Draft08,
            #[cfg(feature = "draft09")]
            SubgroupReaderState::Draft09 => DraftVersion::Draft09,
            #[cfg(feature = "draft10")]
            SubgroupReaderState::Draft10 => DraftVersion::Draft10,
            #[cfg(feature = "draft11")]
            SubgroupReaderState::Draft11 { .. } => DraftVersion::Draft11,
            #[cfg(feature = "draft12")]
            SubgroupReaderState::Draft12 { .. } => DraftVersion::Draft12,
            #[cfg(feature = "draft13")]
            SubgroupReaderState::Draft13 { .. } => DraftVersion::Draft13,
            #[cfg(feature = "draft14")]
            SubgroupReaderState::Draft14(_) => DraftVersion::Draft14,
            #[cfg(feature = "draft15")]
            SubgroupReaderState::Draft15(_) => DraftVersion::Draft15,
            #[cfg(feature = "draft16")]
            SubgroupReaderState::Draft16(_) => DraftVersion::Draft16,
            #[cfg(feature = "draft17")]
            SubgroupReaderState::Draft17(_) => DraftVersion::Draft17,
            #[cfg(feature = "draft18")]
            SubgroupReaderState::Draft18(_) => DraftVersion::Draft18,
            #[cfg(feature = "draft19")]
            SubgroupReaderState::Draft19(_) => DraftVersion::Draft19,
            #[cfg(feature = "draft20")]
            SubgroupReaderState::Draft20(_) => DraftVersion::Draft20,
            #[cfg(feature = "draft21")]
            SubgroupReaderState::Draft21(_) => DraftVersion::Draft21,
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnySubgroupObjectReader has no enabled variants"),
        }
    }

    /// Decode the next object, including its payload.
    ///
    /// Returns [`CodecError::UnexpectedEnd`] when `buf` holds only part of an
    /// object; the reader's state is unspecified after such an error, so
    /// callers that may be fed partial buffers must probe against a clone.
    #[allow(unused_variables, unreachable_code)]
    pub fn read_object(&mut self, buf: &mut impl Buf) -> Result<AnySubgroupObject, CodecError> {
        match &mut self.state {
            #[cfg(feature = "draft07")]
            SubgroupReaderState::Draft07 => sg07::read_object(buf),
            #[cfg(feature = "draft08")]
            SubgroupReaderState::Draft08 => sg08::read_object(buf),
            #[cfg(feature = "draft09")]
            SubgroupReaderState::Draft09 => sg09::read_object(buf),
            #[cfg(feature = "draft10")]
            SubgroupReaderState::Draft10 => sg10::read_object(buf),
            #[cfg(feature = "draft11")]
            SubgroupReaderState::Draft11 { extensions } => sg11::read_object(*extensions, buf),
            #[cfg(feature = "draft12")]
            SubgroupReaderState::Draft12 { extensions } => sg12::read_object(*extensions, buf),
            #[cfg(feature = "draft13")]
            SubgroupReaderState::Draft13 { extensions } => sg13::read_object(*extensions, buf),
            #[cfg(feature = "draft14")]
            SubgroupReaderState::Draft14(inner) => sg14::read_object(inner, buf),
            #[cfg(feature = "draft15")]
            SubgroupReaderState::Draft15(inner) => sg15::read_object(inner, buf),
            #[cfg(feature = "draft16")]
            SubgroupReaderState::Draft16(inner) => sg16::read_object(inner, buf),
            #[cfg(feature = "draft17")]
            SubgroupReaderState::Draft17(inner) => sg17::read_object(inner, buf),
            #[cfg(feature = "draft18")]
            SubgroupReaderState::Draft18(inner) => sg18::read_object(inner, buf),
            #[cfg(feature = "draft19")]
            SubgroupReaderState::Draft19(inner) => sg19::read_object(inner, buf),
            #[cfg(feature = "draft20")]
            SubgroupReaderState::Draft20(inner) => sg20::read_object(inner, buf),
            #[cfg(feature = "draft21")]
            SubgroupReaderState::Draft21(inner) => sg21::read_object(inner, buf),
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnySubgroupObjectReader has no enabled variants"),
        }
    }

    /// Decode the next object's framing without copying its payload.
    ///
    /// Advances `buf` past the whole object exactly as
    /// [`read_object`](Self::read_object) does, but returns only scalars.
    /// This is the path a relay uses when it forwards the object's bytes
    /// verbatim and never inspects the payload.
    #[allow(unused_variables, unreachable_code)]
    pub fn read_object_meta(
        &mut self,
        buf: &mut impl Buf,
    ) -> Result<AnySubgroupObjectMeta, CodecError> {
        match &mut self.state {
            #[cfg(feature = "draft07")]
            SubgroupReaderState::Draft07 => sg07::read_object_meta(buf),
            #[cfg(feature = "draft08")]
            SubgroupReaderState::Draft08 => sg08::read_object_meta(buf),
            #[cfg(feature = "draft09")]
            SubgroupReaderState::Draft09 => sg09::read_object_meta(buf),
            #[cfg(feature = "draft10")]
            SubgroupReaderState::Draft10 => sg10::read_object_meta(buf),
            #[cfg(feature = "draft11")]
            SubgroupReaderState::Draft11 { extensions } => sg11::read_object_meta(*extensions, buf),
            #[cfg(feature = "draft12")]
            SubgroupReaderState::Draft12 { extensions } => sg12::read_object_meta(*extensions, buf),
            #[cfg(feature = "draft13")]
            SubgroupReaderState::Draft13 { extensions } => sg13::read_object_meta(*extensions, buf),
            #[cfg(feature = "draft14")]
            SubgroupReaderState::Draft14(inner) => sg14::read_object_meta(inner, buf),
            #[cfg(feature = "draft15")]
            SubgroupReaderState::Draft15(inner) => sg15::read_object_meta(inner, buf),
            #[cfg(feature = "draft16")]
            SubgroupReaderState::Draft16(inner) => sg16::read_object_meta(inner, buf),
            #[cfg(feature = "draft17")]
            SubgroupReaderState::Draft17(inner) => sg17::read_object_meta(inner, buf),
            #[cfg(feature = "draft18")]
            SubgroupReaderState::Draft18(inner) => sg18::read_object_meta(inner, buf),
            #[cfg(feature = "draft19")]
            SubgroupReaderState::Draft19(inner) => sg19::read_object_meta(inner, buf),
            #[cfg(feature = "draft20")]
            SubgroupReaderState::Draft20(inner) => sg20::read_object_meta(inner, buf),
            #[cfg(feature = "draft21")]
            SubgroupReaderState::Draft21(inner) => sg21::read_object_meta(inner, buf),
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnySubgroupObjectReader has no enabled variants"),
        }
    }
}

// ── Subgroup object writer ──────────────────────────────────

/// Per-draft writer state. Mirrors [`SubgroupReaderState`]; drafts 14-21
/// reuse each draft's `SubgroupObjectReader`, which owns both directions of
/// the delta state. Drafts 07-13 encode absolute IDs, so nothing on the wire
/// forces them to increase and they carry a `prev_object_id` of their own —
/// see `advance_absolute_id`.
#[derive(Debug, Clone)]
enum SubgroupWriterState {
    #[cfg(feature = "draft07")]
    Draft07 { prev_object_id: Option<u64> },
    #[cfg(feature = "draft08")]
    Draft08 { prev_object_id: Option<u64> },
    #[cfg(feature = "draft09")]
    Draft09 { prev_object_id: Option<u64> },
    #[cfg(feature = "draft10")]
    Draft10 { prev_object_id: Option<u64> },
    #[cfg(feature = "draft11")]
    Draft11 { extensions: bool, prev_object_id: Option<u64> },
    #[cfg(feature = "draft12")]
    Draft12 { extensions: bool, prev_object_id: Option<u64> },
    #[cfg(feature = "draft13")]
    Draft13 { extensions: bool, prev_object_id: Option<u64> },
    #[cfg(feature = "draft14")]
    Draft14 { inner: crate::draft14::data_stream::SubgroupObjectReader, extensions: bool },
    #[cfg(feature = "draft15")]
    Draft15 { inner: crate::draft15::data_stream::SubgroupObjectReader, extensions: bool },
    #[cfg(feature = "draft16")]
    Draft16 { inner: crate::draft16::data_stream::SubgroupObjectReader, extensions: bool },
    #[cfg(feature = "draft17")]
    Draft17 { inner: crate::draft17::data_stream::SubgroupObjectReader, extensions: bool },
    #[cfg(feature = "draft18")]
    Draft18 { inner: crate::draft18::data_stream::SubgroupObjectReader, extensions: bool },
    #[cfg(feature = "draft19")]
    Draft19 { inner: crate::draft19::data_stream::SubgroupObjectReader, extensions: bool },
    #[cfg(feature = "draft20")]
    Draft20 { inner: crate::draft20::data_stream::SubgroupObjectReader, extensions: bool },
    #[cfg(feature = "draft21")]
    Draft21 { inner: crate::draft21::data_stream::SubgroupObjectReader, extensions: bool },
}

/// Serializer for the objects on a subgroup data stream, for any enabled
/// draft.
///
/// Mirrors [`AnySubgroupObjectReader`]. On drafts 14-21 it tracks the
/// previous Object ID so successive writes produce correct deltas; on drafts
/// 07-13 object IDs are absolute and the same state only enforces that they
/// increase.
///
/// # Eliding objects
///
/// To remove an object from a stream, read it and then simply do not write
/// it. The writer's delta state advances only when
/// [`write_object`](Self::write_object) succeeds, so the next object written
/// re-derives its delta against the last *retained* object automatically.
/// See [`Self::write_object`] for the exact invariant.
#[derive(Debug, Clone)]
pub struct AnySubgroupObjectWriter {
    state: SubgroupWriterState,
}

impl AnySubgroupObjectWriter {
    /// Create a writer for a stream with the given header.
    ///
    /// The header fixes the extension-presence and (on drafts 11-13) stream
    /// type used for every object written, exactly as it does for
    /// [`AnySubgroupObjectReader::new`].
    #[allow(unused_variables, unreachable_code)]
    pub fn new(header: &AnySubgroupHeader) -> Result<Self, CodecError> {
        let state = match header {
            #[cfg(feature = "draft07")]
            AnySubgroupHeader::Draft07(_) => SubgroupWriterState::Draft07 { prev_object_id: None },
            #[cfg(feature = "draft08")]
            AnySubgroupHeader::Draft08(_) => SubgroupWriterState::Draft08 { prev_object_id: None },
            #[cfg(feature = "draft09")]
            AnySubgroupHeader::Draft09(_) => SubgroupWriterState::Draft09 { prev_object_id: None },
            #[cfg(feature = "draft10")]
            AnySubgroupHeader::Draft10(_) => SubgroupWriterState::Draft10 { prev_object_id: None },
            #[cfg(feature = "draft11")]
            AnySubgroupHeader::Draft11(h) => SubgroupWriterState::Draft11 {
                extensions: subgroup_extensions_11(h)?,
                prev_object_id: None,
            },
            #[cfg(feature = "draft12")]
            AnySubgroupHeader::Draft12(h) => SubgroupWriterState::Draft12 {
                extensions: subgroup_extensions_12(h)?,
                prev_object_id: None,
            },
            #[cfg(feature = "draft13")]
            AnySubgroupHeader::Draft13(h) => SubgroupWriterState::Draft13 {
                extensions: subgroup_extensions_13(h)?,
                prev_object_id: None,
            },
            #[cfg(feature = "draft14")]
            AnySubgroupHeader::Draft14(h) => SubgroupWriterState::Draft14 {
                inner: crate::draft14::data_stream::SubgroupObjectReader::new(h),
                extensions: h.stream_type.extensions_present(),
            },
            #[cfg(feature = "draft15")]
            AnySubgroupHeader::Draft15(h) => SubgroupWriterState::Draft15 {
                inner: crate::draft15::data_stream::SubgroupObjectReader::new(h),
                extensions: h.has_extensions(),
            },
            #[cfg(feature = "draft16")]
            AnySubgroupHeader::Draft16(h) => SubgroupWriterState::Draft16 {
                inner: crate::draft16::data_stream::SubgroupObjectReader::new(h),
                extensions: h.has_extensions(),
            },
            #[cfg(feature = "draft17")]
            AnySubgroupHeader::Draft17(h) => SubgroupWriterState::Draft17 {
                inner: crate::draft17::data_stream::SubgroupObjectReader::new(h),
                extensions: h.has_properties(),
            },
            #[cfg(feature = "draft18")]
            AnySubgroupHeader::Draft18(h) => SubgroupWriterState::Draft18 {
                inner: crate::draft18::data_stream::SubgroupObjectReader::new(h),
                extensions: h.has_properties(),
            },
            #[cfg(feature = "draft19")]
            AnySubgroupHeader::Draft19(h) => SubgroupWriterState::Draft19 {
                inner: crate::draft19::data_stream::SubgroupObjectReader::new(h),
                extensions: h.has_properties(),
            },
            #[cfg(feature = "draft20")]
            AnySubgroupHeader::Draft20(h) => SubgroupWriterState::Draft20 {
                inner: crate::draft20::data_stream::SubgroupObjectReader::new(h),
                extensions: h.has_properties(),
            },
            #[cfg(feature = "draft21")]
            AnySubgroupHeader::Draft21(h) => SubgroupWriterState::Draft21 {
                inner: crate::draft21::data_stream::SubgroupObjectReader::new(h),
                extensions: h.has_properties(),
            },
            #[allow(unreachable_patterns)]
            _ => {
                return Err(CodecError::UnsupportedDraft(format!(
                    "draft {:?} not enabled via feature flag",
                    header.draft()
                )));
            }
        };
        Ok(Self { state })
    }

    /// The draft this writer encodes.
    #[allow(unreachable_code)]
    pub fn draft(&self) -> DraftVersion {
        match &self.state {
            #[cfg(feature = "draft07")]
            SubgroupWriterState::Draft07 { .. } => DraftVersion::Draft07,
            #[cfg(feature = "draft08")]
            SubgroupWriterState::Draft08 { .. } => DraftVersion::Draft08,
            #[cfg(feature = "draft09")]
            SubgroupWriterState::Draft09 { .. } => DraftVersion::Draft09,
            #[cfg(feature = "draft10")]
            SubgroupWriterState::Draft10 { .. } => DraftVersion::Draft10,
            #[cfg(feature = "draft11")]
            SubgroupWriterState::Draft11 { .. } => DraftVersion::Draft11,
            #[cfg(feature = "draft12")]
            SubgroupWriterState::Draft12 { .. } => DraftVersion::Draft12,
            #[cfg(feature = "draft13")]
            SubgroupWriterState::Draft13 { .. } => DraftVersion::Draft13,
            #[cfg(feature = "draft14")]
            SubgroupWriterState::Draft14 { .. } => DraftVersion::Draft14,
            #[cfg(feature = "draft15")]
            SubgroupWriterState::Draft15 { .. } => DraftVersion::Draft15,
            #[cfg(feature = "draft16")]
            SubgroupWriterState::Draft16 { .. } => DraftVersion::Draft16,
            #[cfg(feature = "draft17")]
            SubgroupWriterState::Draft17 { .. } => DraftVersion::Draft17,
            #[cfg(feature = "draft18")]
            SubgroupWriterState::Draft18 { .. } => DraftVersion::Draft18,
            #[cfg(feature = "draft19")]
            SubgroupWriterState::Draft19 { .. } => DraftVersion::Draft19,
            #[cfg(feature = "draft20")]
            SubgroupWriterState::Draft20 { .. } => DraftVersion::Draft20,
            #[cfg(feature = "draft21")]
            SubgroupWriterState::Draft21 { .. } => DraftVersion::Draft21,
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnySubgroupObjectWriter has no enabled variants"),
        }
    }

    /// Encode one object, advancing the delta state.
    ///
    /// # Invariant
    ///
    /// Let a stream's objects decode to absolute IDs `a_0, a_1, .., a_n`.
    /// Feeding any strictly-increasing subsequence of those objects through
    /// one writer, in order, produces a byte stream that decodes back to
    /// exactly that subsequence of absolute IDs, on every draft 07-21.
    ///
    /// Concretely: dropping `a_2` from `0,1,2,3,4` yields a stream decoding
    /// to `0,1,3,4` — not `0,1,2,3`.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] when `object.object_id` is not strictly
    /// greater than the previously written object's ID (two objects on a
    /// subgroup stream can never share an ID, so no valid delta exists), when
    /// a computed delta or length exceeds the varint range, when the object
    /// carries extension bytes that a stream without an extension block
    /// cannot represent, or when a non-empty payload is paired with a status.
    ///
    /// Also [`CodecError::InvalidField`] when `object.status` holds a code the
    /// draft being written does not assign. [`AnySubgroupObject::status`] is a
    /// raw wire code because it crosses drafts, and the assigned set moves
    /// between them, so a status read off one draft's stream is not
    /// necessarily writable onto another's: forwarding a draft-15 Object Does
    /// Not Exist (0x1) onto a draft-16 or later stream is refused here rather
    /// than emitted as a byte the peer must close the session over.
    #[allow(unused_variables, unreachable_code)]
    pub fn write_object(
        &mut self,
        object: &AnySubgroupObject,
        buf: &mut impl BufMut,
    ) -> Result<(), CodecError> {
        match &mut self.state {
            #[cfg(feature = "draft07")]
            SubgroupWriterState::Draft07 { prev_object_id } => {
                advance_absolute_id(prev_object_id, object, |o| sg07::write_object(o, buf))
            }
            #[cfg(feature = "draft08")]
            SubgroupWriterState::Draft08 { prev_object_id } => {
                advance_absolute_id(prev_object_id, object, |o| sg08::write_object(o, buf))
            }
            #[cfg(feature = "draft09")]
            SubgroupWriterState::Draft09 { prev_object_id } => {
                advance_absolute_id(prev_object_id, object, |o| sg09::write_object(o, buf))
            }
            #[cfg(feature = "draft10")]
            SubgroupWriterState::Draft10 { prev_object_id } => {
                advance_absolute_id(prev_object_id, object, |o| sg10::write_object(o, buf))
            }
            #[cfg(feature = "draft11")]
            SubgroupWriterState::Draft11 { extensions, prev_object_id } => {
                let extensions = *extensions;
                advance_absolute_id(prev_object_id, object, |o| {
                    sg11::write_object(extensions, o, buf)
                })
            }
            #[cfg(feature = "draft12")]
            SubgroupWriterState::Draft12 { extensions, prev_object_id } => {
                let extensions = *extensions;
                advance_absolute_id(prev_object_id, object, |o| {
                    sg12::write_object(extensions, o, buf)
                })
            }
            #[cfg(feature = "draft13")]
            SubgroupWriterState::Draft13 { extensions, prev_object_id } => {
                let extensions = *extensions;
                advance_absolute_id(prev_object_id, object, |o| {
                    sg13::write_object(extensions, o, buf)
                })
            }
            #[cfg(feature = "draft14")]
            SubgroupWriterState::Draft14 { inner, extensions } => {
                reject_unrepresentable_extensions(*extensions, object)?;
                sg14::write_object(inner, object, buf)
            }
            #[cfg(feature = "draft15")]
            SubgroupWriterState::Draft15 { inner, extensions } => {
                reject_unrepresentable_extensions(*extensions, object)?;
                sg15::write_object(inner, object, buf)
            }
            #[cfg(feature = "draft16")]
            SubgroupWriterState::Draft16 { inner, extensions } => {
                reject_unrepresentable_extensions(*extensions, object)?;
                sg16::write_object(inner, object, buf)
            }
            #[cfg(feature = "draft17")]
            SubgroupWriterState::Draft17 { inner, extensions } => {
                reject_unrepresentable_extensions(*extensions, object)?;
                sg17::write_object(inner, object, buf)
            }
            #[cfg(feature = "draft18")]
            SubgroupWriterState::Draft18 { inner, extensions } => {
                reject_unrepresentable_extensions(*extensions, object)?;
                sg18::write_object(inner, object, buf)
            }
            #[cfg(feature = "draft19")]
            SubgroupWriterState::Draft19 { inner, extensions } => {
                reject_unrepresentable_extensions(*extensions, object)?;
                sg19::write_object(inner, object, buf)
            }
            #[cfg(feature = "draft20")]
            SubgroupWriterState::Draft20 { inner, extensions } => {
                reject_unrepresentable_extensions(*extensions, object)?;
                sg20::write_object(inner, object, buf)
            }
            #[cfg(feature = "draft21")]
            SubgroupWriterState::Draft21 { inner, extensions } => {
                reject_unrepresentable_extensions(*extensions, object)?;
                sg21::write_object(inner, object, buf)
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnySubgroupObjectWriter has no enabled variants"),
        }
    }
}

// ── Re-emitting an object whose bytes are already known ─────

/// What [`reemit_subgroup_object`] had to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reemit {
    /// The bytes were copied unchanged.
    Verbatim,
    /// Only the leading Object ID field changed.
    Reencoded {
        /// Bytes the ID field occupied in `raw`.
        id_bytes_before: usize,
        /// Bytes it occupies in the output.
        id_bytes_after: usize,
    },
}

/// Re-emit a subgroup object whose wire bytes are already known, adjusting
/// only this draft's encoding of its identity.
///
/// This is the whole of what removing an object from a subgroup stream
/// costs. Drafts 07-13 encode absolute Object IDs, so every survivor's
/// bytes are already correct and this copies `raw` unchanged after checking
/// that IDs still increase. Drafts 14-21 encode `id - prev - 1`, so the
/// leading varint is recomputed against `prev_forwarded`; when its minimal
/// encoding is byte-identical to the one in `raw` the bytes are still
/// copied unchanged. Everything after the ID field — extension block,
/// length, status, payload — is always copied verbatim.
///
/// After one object is re-emitted following an elided run, the writer's
/// cursor re-converges with the reader's, so every later object's original
/// bytes remain correct. An elide therefore costs at most one fix-up, not a
/// re-encode of the stream's tail.
///
/// `prev_forwarded` is the absolute Object ID of the last object actually
/// forwarded on this stream, or `None` when none has been.
///
/// # `raw` need not be a complete object
///
/// **Any prefix is legal provided the whole leading Object ID field is
/// present.** Everything after that field is copied byte-for-byte, however
/// many bytes there are, and **no length validation is performed** — this
/// function never reads the extension block, never reads the payload
/// length field and never compares it to `raw.len()`. It cannot: on drafts
/// 07-13 it does not decode past the ID at all, and on 14-20 it decodes
/// exactly one varint.
///
/// This is what lets a caller fix up the **first chunk of an oversized
/// object** — an object too large to buffer is forwarded in chunks, and only
/// the first one carries the ID field. A caller that cannot guarantee the ID
/// field is whole in the chunk it passes gets
/// [`CodecError::InvalidField`] rather than a silent truncation.
///
/// **Do not add a completeness check.** A `raw.len() >= wire_len` assertion
/// would look defensive, would pass every test that feeds it whole objects,
/// and would refuse the prefix this function exists to accept.
///
/// # Errors
///
/// [`CodecError::InvalidField`] when `object_id` is not strictly greater
/// than `prev_forwarded`, when the recomputed delta exceeds the varint
/// range, or when `raw` does not begin with a decodable varint — which
/// includes a `raw` too short to hold the whole leading varint.
///
/// # Examples
///
/// ```
/// use moqtap_codec::dispatch::{reemit_subgroup_object, Reemit};
/// use moqtap_codec::version::DraftVersion;
///
/// // A draft-19 object that was encoded as the successor of ID 4 —
/// // leading delta 0 — re-emitted after ID 3 was the last one forwarded.
/// let raw = [0x00, 0x02, 0xca, 0xfe];
/// let mut out = Vec::new();
/// let what = reemit_subgroup_object(DraftVersion::Draft19, Some(3), 5, &raw, &mut out).unwrap();
/// assert_eq!(what, Reemit::Reencoded { id_bytes_before: 1, id_bytes_after: 1 });
/// assert_eq!(out, [0x01, 0x02, 0xca, 0xfe]);
/// ```
pub fn reemit_subgroup_object(
    draft: DraftVersion,
    prev_forwarded: Option<u64>,
    object_id: u64,
    raw: &[u8],
    out: &mut impl BufMut,
) -> Result<Reemit, CodecError> {
    if matches!(prev_forwarded, Some(prev) if object_id <= prev) {
        return Err(CodecError::InvalidField);
    }

    // Measure the ID field. Every draft 07-21 puts it first and nothing past
    // it is decoded, so `raw` may stop anywhere after it. Which varint measures
    // it depends on the draft: 17 replaced the RFC 9000 encoding with MoQT's.
    let mut cursor: &[u8] = raw;
    draft.decode_varint(&mut cursor).map_err(|_| CodecError::InvalidField)?;
    let id_bytes_before = raw.len() - cursor.len();

    // Drafts 07-13 write the ID absolutely: nothing about that field depends
    // on which objects were forwarded, so the bytes already say the truth.
    if !delta_encodes_object_ids(draft) {
        out.put_slice(raw);
        return Ok(Reemit::Verbatim);
    }

    let delta = match prev_forwarded {
        None => object_id,
        Some(prev) => object_id
            .checked_sub(prev)
            .and_then(|v| v.checked_sub(1))
            .ok_or(CodecError::InvalidField)?,
    };

    // The MoQT encoding reaches the full 64-bit range, so a delta a draft-17+
    // peer can legitimately send is not an error there.
    let field = if draft.uses_moqt_varint() {
        VarInt::from_u64_moqt(delta)
    } else {
        VarInt::from_u64(delta).map_err(|_| CodecError::InvalidField)?
    };

    // Nine bytes: the MoQT encoding is one longer than RFC 9000 at the top.
    let mut encoded = [0u8; 9];
    let mut slot: &mut [u8] = &mut encoded;
    draft.encode_varint(field, &mut slot);
    let id_bytes_after = 9 - slot.len();
    let encoded = &encoded[..id_bytes_after];

    if encoded == &raw[..id_bytes_before] {
        out.put_slice(raw);
        return Ok(Reemit::Verbatim);
    }

    out.put_slice(encoded);
    out.put_slice(&raw[id_bytes_before..]);
    Ok(Reemit::Reencoded { id_bytes_before, id_bytes_after })
}

/// `true` on the drafts whose subgroup objects encode the Object ID as
/// `id - prev - 1` rather than absolutely.
///
/// Needs no `#[cfg]`: [`DraftVersion`] is not feature-gated, so this answers
/// for a draft whose codec is not compiled in.
fn delta_encodes_object_ids(draft: DraftVersion) -> bool {
    matches!(
        draft,
        DraftVersion::Draft14
            | DraftVersion::Draft15
            | DraftVersion::Draft16
            | DraftVersion::Draft17
            | DraftVersion::Draft18
            | DraftVersion::Draft19
            | DraftVersion::Draft20
            | DraftVersion::Draft21
    )
}

/// Enforce the strictly-increasing Object ID rule on the drafts that encode
/// IDs absolutely.
///
/// Drafts 14-21 get this for free: their delta is `id - prev - 1`, so a
/// repeated or decreasing ID underflows and the per-draft writer rejects it.
/// Drafts 07-13 write the ID verbatim and would happily emit a stream no
/// publisher can produce, so the check lives here. As on the delta drafts, the
/// state advances only once the object is actually written, which is what makes
/// elision *read it and do not write it*.
#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13"
))]
fn advance_absolute_id(
    prev_object_id: &mut Option<u64>,
    object: &AnySubgroupObject,
    write: impl FnOnce(&AnySubgroupObject) -> Result<(), CodecError>,
) -> Result<(), CodecError> {
    if matches!(*prev_object_id, Some(prev) if object.object_id <= prev) {
        return Err(CodecError::InvalidField);
    }
    write(object)?;
    *prev_object_id = Some(object.object_id);
    Ok(())
}

/// A stream whose header says objects carry no extension block cannot encode
/// one, so refuse rather than drop the bytes.
#[cfg(any(
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
fn reject_unrepresentable_extensions(
    extensions: bool,
    object: &AnySubgroupObject,
) -> Result<(), CodecError> {
    if !extensions && !object.extension_headers.is_empty() {
        return Err(CodecError::InvalidField);
    }
    Ok(())
}

// ── Fetch object reader ─────────────────────────────────────

/// Per-draft fetch reader state. Fetch objects are self-describing on drafts
/// 07-14, so those variants carry none; drafts 15-21 let an object take fields
/// from the one before it, so each owns the running state that resolves them.
#[derive(Debug, Clone)]
enum FetchReaderState {
    #[cfg(feature = "draft07")]
    Draft07,
    #[cfg(feature = "draft08")]
    Draft08,
    #[cfg(feature = "draft09")]
    Draft09,
    #[cfg(feature = "draft10")]
    Draft10,
    #[cfg(feature = "draft11")]
    Draft11,
    #[cfg(feature = "draft12")]
    Draft12,
    #[cfg(feature = "draft13")]
    Draft13,
    #[cfg(feature = "draft14")]
    Draft14,
    #[cfg(feature = "draft15")]
    Draft15(crate::draft15::data_stream::FetchObjectReader),
    #[cfg(feature = "draft16")]
    Draft16(crate::draft16::data_stream::FetchObjectReader),
    #[cfg(feature = "draft17")]
    Draft17(crate::draft17::data_stream::FetchObjectReader),
    #[cfg(feature = "draft18")]
    Draft18(crate::draft18::data_stream::FetchObjectReader),
    #[cfg(feature = "draft19")]
    Draft19(crate::draft19::data_stream::FetchObjectReader),
    #[cfg(feature = "draft20")]
    Draft20(crate::draft20::data_stream::FetchObjectReader),
    #[cfg(feature = "draft21")]
    Draft21(crate::draft21::data_stream::FetchObjectReader),
}

/// Stateful reader for the frames on a fetch data stream, for any enabled
/// draft.
///
/// Fetch objects are self-describing on drafts 07-14 and this reader carries no
/// state there. From draft-15 a Serialization Flags field decides which of an
/// object's Group ID, Subgroup ID, Object ID and Priority reach the wire at
/// all, and every field it omits is the object before it on the stream —
/// repeated, or stepped by one, or (from draft-18) counted from by a
/// difference. This reader holds that running state, so the values it produces
/// are absolute on every draft.
///
/// One reader belongs to one stream. Every draft counts "the prior Object"
/// along a single stream, so sharing a reader between streams, or restarting
/// one mid-stream, resolves later frames onto the wrong group, subgroup, ID or
/// priority — usually without an error anywhere.
///
/// The reader is [`Clone`] specifically so callers can probe a partial buffer
/// against a copy and commit only on success; see the module docs.
///
/// # Frames that are not objects
///
/// Drafts 16-21 add End of Range indicators, which state that a run of Objects
/// was not serialized. They arrive through the same calls as objects and are
/// told apart by [`AnyFetchObject::end_of_range`].
#[derive(Debug, Clone)]
pub struct AnyFetchObjectReader {
    state: FetchReaderState,
}

impl AnyFetchObjectReader {
    /// Create a reader from the stream's fetch header and the Group Order the
    /// fetch was opened with.
    ///
    /// The order matters only on drafts 18 and 19, where an Object's Group ID
    /// is a difference from the previous Object's and the order decides its
    /// sign. Nothing on the data stream carries it — the FETCH settles it — and
    /// it is an argument rather than a default because a descending stream read
    /// as ascending does not fail: it decodes, under Group IDs walking the wrong
    /// way, and neither this crate nor the caller can tell afterwards. Both
    /// readings are legal streams.
    ///
    /// [`AnyControlMessage::fetch_group_order`](crate::dispatch::AnyControlMessage::fetch_group_order)
    /// answers it from the FETCH, including the case where the message names no
    /// GROUP_ORDER — draft-19 Section 10.2.8: "If omitted from FETCH, the
    /// receiver uses Ascending (0x1)". On drafts 07-17 the argument is ignored.
    ///
    /// Returns [`CodecError::UnsupportedDraft`] for drafts not compiled in.
    #[allow(unused_variables, unreachable_code)]
    pub fn new(
        header: &AnyFetchHeader,
        group_order: AnyFetchGroupOrder,
    ) -> Result<Self, CodecError> {
        let state = match header {
            #[cfg(feature = "draft07")]
            AnyFetchHeader::Draft07(_) => FetchReaderState::Draft07,
            #[cfg(feature = "draft08")]
            AnyFetchHeader::Draft08(_) => FetchReaderState::Draft08,
            #[cfg(feature = "draft09")]
            AnyFetchHeader::Draft09(_) => FetchReaderState::Draft09,
            #[cfg(feature = "draft10")]
            AnyFetchHeader::Draft10(_) => FetchReaderState::Draft10,
            #[cfg(feature = "draft11")]
            AnyFetchHeader::Draft11(_) => FetchReaderState::Draft11,
            #[cfg(feature = "draft12")]
            AnyFetchHeader::Draft12(_) => FetchReaderState::Draft12,
            #[cfg(feature = "draft13")]
            AnyFetchHeader::Draft13(_) => FetchReaderState::Draft13,
            #[cfg(feature = "draft14")]
            AnyFetchHeader::Draft14(_) => FetchReaderState::Draft14,
            // The header carries only a request id on drafts 15-21, so nothing
            // about it seeds the reader; the first object does.
            #[cfg(feature = "draft15")]
            AnyFetchHeader::Draft15(_) => {
                FetchReaderState::Draft15(crate::draft15::data_stream::FetchObjectReader::new())
            }
            #[cfg(feature = "draft16")]
            AnyFetchHeader::Draft16(_) => {
                FetchReaderState::Draft16(crate::draft16::data_stream::FetchObjectReader::new())
            }
            #[cfg(feature = "draft17")]
            AnyFetchHeader::Draft17(_) => {
                FetchReaderState::Draft17(crate::draft17::data_stream::FetchObjectReader::new())
            }
            #[cfg(feature = "draft18")]
            AnyFetchHeader::Draft18(_) => FetchReaderState::Draft18(
                crate::draft18::data_stream::FetchObjectReader::new(match group_order {
                    AnyFetchGroupOrder::Ascending => {
                        crate::draft18::data_stream::GroupOrder::Ascending
                    }
                    AnyFetchGroupOrder::Descending => {
                        crate::draft18::data_stream::GroupOrder::Descending
                    }
                }),
            ),
            #[cfg(feature = "draft19")]
            AnyFetchHeader::Draft19(_) => FetchReaderState::Draft19(
                crate::draft19::data_stream::FetchObjectReader::new(match group_order {
                    AnyFetchGroupOrder::Ascending => {
                        crate::draft19::data_stream::GroupOrder::Ascending
                    }
                    AnyFetchGroupOrder::Descending => {
                        crate::draft19::data_stream::GroupOrder::Descending
                    }
                }),
            ),
            #[cfg(feature = "draft20")]
            AnyFetchHeader::Draft20(_) => FetchReaderState::Draft20(
                crate::draft20::data_stream::FetchObjectReader::new(match group_order {
                    AnyFetchGroupOrder::Ascending => {
                        crate::draft20::data_stream::GroupOrder::Ascending
                    }
                    AnyFetchGroupOrder::Descending => {
                        crate::draft20::data_stream::GroupOrder::Descending
                    }
                }),
            ),
            #[cfg(feature = "draft21")]
            AnyFetchHeader::Draft21(_) => FetchReaderState::Draft21(
                crate::draft21::data_stream::FetchObjectReader::new(match group_order {
                    AnyFetchGroupOrder::Ascending => {
                        crate::draft21::data_stream::GroupOrder::Ascending
                    }
                    AnyFetchGroupOrder::Descending => {
                        crate::draft21::data_stream::GroupOrder::Descending
                    }
                }),
            ),
            #[allow(unreachable_patterns)]
            _ => {
                return Err(CodecError::UnsupportedDraft(format!(
                    "draft {:?} not enabled via feature flag",
                    header.draft()
                )));
            }
        };
        Ok(Self { state })
    }

    /// The draft this reader decodes.
    #[allow(unreachable_code)]
    pub fn draft(&self) -> DraftVersion {
        match &self.state {
            #[cfg(feature = "draft07")]
            FetchReaderState::Draft07 => DraftVersion::Draft07,
            #[cfg(feature = "draft08")]
            FetchReaderState::Draft08 => DraftVersion::Draft08,
            #[cfg(feature = "draft09")]
            FetchReaderState::Draft09 => DraftVersion::Draft09,
            #[cfg(feature = "draft10")]
            FetchReaderState::Draft10 => DraftVersion::Draft10,
            #[cfg(feature = "draft11")]
            FetchReaderState::Draft11 => DraftVersion::Draft11,
            #[cfg(feature = "draft12")]
            FetchReaderState::Draft12 => DraftVersion::Draft12,
            #[cfg(feature = "draft13")]
            FetchReaderState::Draft13 => DraftVersion::Draft13,
            #[cfg(feature = "draft14")]
            FetchReaderState::Draft14 => DraftVersion::Draft14,
            #[cfg(feature = "draft15")]
            FetchReaderState::Draft15(_) => DraftVersion::Draft15,
            #[cfg(feature = "draft16")]
            FetchReaderState::Draft16(_) => DraftVersion::Draft16,
            #[cfg(feature = "draft17")]
            FetchReaderState::Draft17(_) => DraftVersion::Draft17,
            #[cfg(feature = "draft18")]
            FetchReaderState::Draft18(_) => DraftVersion::Draft18,
            #[cfg(feature = "draft19")]
            FetchReaderState::Draft19(_) => DraftVersion::Draft19,
            #[cfg(feature = "draft20")]
            FetchReaderState::Draft20(_) => DraftVersion::Draft20,
            #[cfg(feature = "draft21")]
            FetchReaderState::Draft21(_) => DraftVersion::Draft21,
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyFetchObjectReader has no enabled variants"),
        }
    }

    /// Decode the next fetch frame, including its payload.
    ///
    /// Returns [`CodecError::UnexpectedEnd`] when `buf` holds only part of a
    /// frame; the reader's state is unspecified after such an error, so callers
    /// that may be fed partial buffers must probe against a clone.
    ///
    /// Returns [`CodecError::InvalidField`] on drafts 15-21 when a frame takes
    /// a field from an object before it that does not exist — the first frame
    /// of a stream doing so is a protocol violation on every one of those
    /// drafts — and when a resolved Group ID, Subgroup ID or Object ID would
    /// leave the 64-bit range.
    #[allow(unused_variables, unreachable_code)]
    pub fn read_object(&mut self, buf: &mut impl Buf) -> Result<AnyFetchObject, CodecError> {
        match &mut self.state {
            #[cfg(feature = "draft07")]
            FetchReaderState::Draft07 => fo07::read_object(buf),
            #[cfg(feature = "draft08")]
            FetchReaderState::Draft08 => fo08::read_object(buf),
            #[cfg(feature = "draft09")]
            FetchReaderState::Draft09 => fo09::read_object(buf),
            #[cfg(feature = "draft10")]
            FetchReaderState::Draft10 => fo10::read_object(buf),
            #[cfg(feature = "draft11")]
            FetchReaderState::Draft11 => fo11::read_object(buf),
            #[cfg(feature = "draft12")]
            FetchReaderState::Draft12 => fo12::read_object(buf),
            #[cfg(feature = "draft13")]
            FetchReaderState::Draft13 => fo13::read_object(buf),
            #[cfg(feature = "draft14")]
            FetchReaderState::Draft14 => fo14::read_object(buf),
            #[cfg(feature = "draft15")]
            FetchReaderState::Draft15(inner) => fo15::read_object(inner, buf),
            #[cfg(feature = "draft16")]
            FetchReaderState::Draft16(inner) => fo16::read_object(inner, buf),
            #[cfg(feature = "draft17")]
            FetchReaderState::Draft17(inner) => fo17::read_object(inner, buf),
            #[cfg(feature = "draft18")]
            FetchReaderState::Draft18(inner) => fo18::read_object(inner, buf),
            #[cfg(feature = "draft19")]
            FetchReaderState::Draft19(inner) => fo19::read_object(inner, buf),
            #[cfg(feature = "draft20")]
            FetchReaderState::Draft20(inner) => fo20::read_object(inner, buf),
            #[cfg(feature = "draft21")]
            FetchReaderState::Draft21(inner) => fo21::read_object(inner, buf),
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyFetchObjectReader has no enabled variants"),
        }
    }

    /// Decode the next fetch frame, keeping what re-encoding it later takes.
    ///
    /// Advances `buf` and this reader exactly as
    /// [`read_object_meta`](Self::read_object_meta) does, and reports the same
    /// framing in [`AnyFetchFrame::meta`]. What it additionally keeps is the
    /// shape the frame arrived in, which is the whole of what
    /// [`AnyFetchObjectWriter::reemit_object`] needs to write the frame back
    /// out against a different predecessor.
    ///
    /// Costs nothing over `read_object_meta`, which is itself defined over
    /// this: the per-draft header it keeps is one the decode produced and
    /// dropped.
    #[allow(unused_variables, unreachable_code)]
    pub fn read_object_frame(&mut self, buf: &mut impl Buf) -> Result<AnyFetchFrame, CodecError> {
        match &mut self.state {
            #[cfg(feature = "draft07")]
            FetchReaderState::Draft07 => fo07::read_object_meta(buf)
                .map(|meta| AnyFetchFrame::absolute(DraftVersion::Draft07, meta)),
            #[cfg(feature = "draft08")]
            FetchReaderState::Draft08 => fo08::read_object_meta(buf)
                .map(|meta| AnyFetchFrame::absolute(DraftVersion::Draft08, meta)),
            #[cfg(feature = "draft09")]
            FetchReaderState::Draft09 => fo09::read_object_meta(buf)
                .map(|meta| AnyFetchFrame::absolute(DraftVersion::Draft09, meta)),
            #[cfg(feature = "draft10")]
            FetchReaderState::Draft10 => fo10::read_object_meta(buf)
                .map(|meta| AnyFetchFrame::absolute(DraftVersion::Draft10, meta)),
            #[cfg(feature = "draft11")]
            FetchReaderState::Draft11 => fo11::read_object_meta(buf)
                .map(|meta| AnyFetchFrame::absolute(DraftVersion::Draft11, meta)),
            #[cfg(feature = "draft12")]
            FetchReaderState::Draft12 => fo12::read_object_meta(buf)
                .map(|meta| AnyFetchFrame::absolute(DraftVersion::Draft12, meta)),
            #[cfg(feature = "draft13")]
            FetchReaderState::Draft13 => fo13::read_object_meta(buf)
                .map(|meta| AnyFetchFrame::absolute(DraftVersion::Draft13, meta)),
            #[cfg(feature = "draft14")]
            FetchReaderState::Draft14 => fo14::read_object_meta(buf)
                .map(|meta| AnyFetchFrame::absolute(DraftVersion::Draft14, meta)),
            #[cfg(feature = "draft15")]
            FetchReaderState::Draft15(inner) => fo15::read_object_frame(inner, buf),
            #[cfg(feature = "draft16")]
            FetchReaderState::Draft16(inner) => fo16::read_object_frame(inner, buf),
            #[cfg(feature = "draft17")]
            FetchReaderState::Draft17(inner) => fo17::read_object_frame(inner, buf),
            #[cfg(feature = "draft18")]
            FetchReaderState::Draft18(inner) => fo18::read_object_frame(inner, buf),
            #[cfg(feature = "draft19")]
            FetchReaderState::Draft19(inner) => fo19::read_object_frame(inner, buf),
            #[cfg(feature = "draft20")]
            FetchReaderState::Draft20(inner) => fo20::read_object_frame(inner, buf),
            #[cfg(feature = "draft21")]
            FetchReaderState::Draft21(inner) => fo21::read_object_frame(inner, buf),
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyFetchObjectReader has no enabled variants"),
        }
    }

    /// Decode the next fetch frame's framing without copying its payload.
    ///
    /// Advances `buf` past the whole frame exactly as
    /// [`read_object`](Self::read_object) does, and advances the same reader
    /// state, so the two are interchangeable on one stream.
    #[allow(unused_variables, unreachable_code)]
    pub fn read_object_meta(
        &mut self,
        buf: &mut impl Buf,
    ) -> Result<AnyFetchObjectMeta, CodecError> {
        match &mut self.state {
            #[cfg(feature = "draft07")]
            FetchReaderState::Draft07 => fo07::read_object_meta(buf),
            #[cfg(feature = "draft08")]
            FetchReaderState::Draft08 => fo08::read_object_meta(buf),
            #[cfg(feature = "draft09")]
            FetchReaderState::Draft09 => fo09::read_object_meta(buf),
            #[cfg(feature = "draft10")]
            FetchReaderState::Draft10 => fo10::read_object_meta(buf),
            #[cfg(feature = "draft11")]
            FetchReaderState::Draft11 => fo11::read_object_meta(buf),
            #[cfg(feature = "draft12")]
            FetchReaderState::Draft12 => fo12::read_object_meta(buf),
            #[cfg(feature = "draft13")]
            FetchReaderState::Draft13 => fo13::read_object_meta(buf),
            #[cfg(feature = "draft14")]
            FetchReaderState::Draft14 => fo14::read_object_meta(buf),
            #[cfg(feature = "draft15")]
            FetchReaderState::Draft15(inner) => fo15::read_object_meta(inner, buf),
            #[cfg(feature = "draft16")]
            FetchReaderState::Draft16(inner) => fo16::read_object_meta(inner, buf),
            #[cfg(feature = "draft17")]
            FetchReaderState::Draft17(inner) => fo17::read_object_meta(inner, buf),
            #[cfg(feature = "draft18")]
            FetchReaderState::Draft18(inner) => fo18::read_object_meta(inner, buf),
            #[cfg(feature = "draft19")]
            FetchReaderState::Draft19(inner) => fo19::read_object_meta(inner, buf),
            #[cfg(feature = "draft20")]
            FetchReaderState::Draft20(inner) => fo20::read_object_meta(inner, buf),
            #[cfg(feature = "draft21")]
            FetchReaderState::Draft21(inner) => fo21::read_object_meta(inner, buf),
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyFetchObjectReader has no enabled variants"),
        }
    }
}

// ── Carrying a fetch frame from a reader to a writer ────────

/// Per-draft capture of the shape one fetch frame arrived in.
///
/// Drafts 07-14 keep nothing: every field of a fetch object is on their wire
/// outright, so the bytes say the same thing whatever precedes them. Drafts
/// 15-21 keep the frame's own header, and draft-16 the resolved Location
/// beside it, because those two are exactly what each draft's
/// `FetchObjectWriter` is handed.
#[derive(Debug, Clone)]
enum FetchFrameShape {
    /// A frame whose fields are all absolute.
    #[cfg(any(
        feature = "draft07",
        feature = "draft08",
        feature = "draft09",
        feature = "draft10",
        feature = "draft11",
        feature = "draft12",
        feature = "draft13",
        feature = "draft14"
    ))]
    Absolute,
    #[cfg(feature = "draft15")]
    Draft15(crate::draft15::data_stream::FetchObjectHeader),
    #[cfg(feature = "draft16")]
    Draft16(
        crate::draft16::data_stream::FetchObjectHeader,
        crate::draft16::data_stream::FetchObjectLocation,
    ),
    #[cfg(feature = "draft17")]
    Draft17(crate::draft17::data_stream::FetchObject),
    #[cfg(feature = "draft18")]
    Draft18(crate::draft18::data_stream::FetchObject),
    #[cfg(feature = "draft19")]
    Draft19(crate::draft19::data_stream::FetchObject),
    #[cfg(feature = "draft20")]
    Draft20(crate::draft20::data_stream::FetchObject),
    #[cfg(feature = "draft21")]
    Draft21(crate::draft21::data_stream::FetchObject),
}

/// One fetch frame, in the form re-encoding it takes.
///
/// Produced by [`AnyFetchObjectReader::read_object_frame`] and consumed by
/// [`AnyFetchObjectWriter::reemit_object`]. It is one value rather than two
/// because a frame's resolved identity and the shape it arrived in are only
/// meaningful together: the first says what the frame *is*, the second is the
/// encoding a writer keeps wherever it still says the same thing, and that is
/// what reproduces an untouched stream byte for byte.
#[derive(Debug, Clone)]
pub struct AnyFetchFrame {
    /// The framing, exactly as [`AnyFetchObjectReader::read_object_meta`]
    /// reports it.
    pub meta: AnyFetchObjectMeta,
    draft: DraftVersion,
    shape: FetchFrameShape,
}

impl AnyFetchFrame {
    /// The draft whose stream this frame was read off.
    ///
    /// A writer refuses a frame from any other draft rather than re-encoding
    /// it: the two would agree on the resolved Location and disagree on
    /// everything the flags mean.
    #[must_use]
    pub fn draft(&self) -> DraftVersion {
        self.draft
    }

    /// A frame from one of the drafts that keeps nothing.
    #[cfg(any(
        feature = "draft07",
        feature = "draft08",
        feature = "draft09",
        feature = "draft10",
        feature = "draft11",
        feature = "draft12",
        feature = "draft13",
        feature = "draft14"
    ))]
    fn absolute(draft: DraftVersion, meta: AnyFetchObjectMeta) -> Self {
        Self { meta, draft, shape: FetchFrameShape::Absolute }
    }
}

// ── Fetch object writer ─────────────────────────────────────

/// What [`AnyFetchObjectWriter::reemit_object`] had to do.
///
/// The counterpart of [`Reemit`], and deliberately not the same type. A
/// subgroup object's fix-up rewrites one leading varint and always writes the
/// whole object out; a fetch frame's is a re-encode of the whole header, and
/// the case worth having a shape for is the one where no re-encode is owed and
/// nothing is written at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchReemit {
    /// The frame's own bytes still encode it against the frame now in front of
    /// it, so **nothing was written** and the caller forwards `raw` untouched.
    ///
    /// This is every frame on a stream nothing was removed from, which is why
    /// it writes nothing: a relay that copied each frame through an output
    /// buffer to discover it would copy every payload it forwards.
    Unchanged,
    /// New framing was needed. The whole frame — the new framing followed by
    /// every byte of `raw` behind the old — was written to `out`, and the
    /// caller forwards that instead of `raw`.
    Reframed {
        /// Bytes the framing occupied in `raw`.
        framing_bytes_before: usize,
        /// Bytes it occupies in the output.
        framing_bytes_after: usize,
    },
}

/// Per-draft writer state, mirroring [`FetchReaderState`].
#[derive(Debug, Clone)]
enum FetchWriterState {
    /// Drafts 07-14, which write every field of a fetch object outright and
    /// have nothing to write one *against*. The draft is carried so that a
    /// frame from another one is still refused.
    #[cfg(any(
        feature = "draft07",
        feature = "draft08",
        feature = "draft09",
        feature = "draft10",
        feature = "draft11",
        feature = "draft12",
        feature = "draft13",
        feature = "draft14"
    ))]
    Absolute(DraftVersion),
    #[cfg(feature = "draft15")]
    Draft15(crate::draft15::data_stream::FetchObjectWriter),
    #[cfg(feature = "draft16")]
    Draft16(crate::draft16::data_stream::FetchObjectWriter),
    #[cfg(feature = "draft17")]
    Draft17(crate::draft17::data_stream::FetchObjectWriter),
    #[cfg(feature = "draft18")]
    Draft18(crate::draft18::data_stream::FetchObjectWriter),
    #[cfg(feature = "draft19")]
    Draft19(crate::draft19::data_stream::FetchObjectWriter),
    #[cfg(feature = "draft20")]
    Draft20(crate::draft20::data_stream::FetchObjectWriter),
    #[cfg(feature = "draft21")]
    Draft21(crate::draft21::data_stream::FetchObjectWriter),
}

/// Re-emitter for the frames of a fetch data stream, for any enabled draft.
///
/// The inverse of [`AnyFetchObjectReader`], and it exists for one caller: a
/// relay reading one fetch stream and writing another from the same frames,
/// having removed some of them. Removing a frame changes what the frames
/// behind it are encoded *against*, and on drafts 15-21 nearly every field of
/// a fetch object is defined against the frame before it — draft-17
/// Section 10.4.4.1, Table 7: "Object ID is the prior Object's ID plus one" —
/// so a survivor following a removed run cannot keep its original bytes.
///
/// # How it is driven
///
/// One writer belongs to one stream, and [`reemit_object`](Self::reemit_object)
/// is called **for every frame the caller forwards**, in wire order, whether or
/// not anything has been removed yet. That call is what moves the writer, so a
/// forwarded frame it never saw leaves it a frame behind and re-encodes the
/// next survivor against the wrong predecessor. A frame the caller *elides* is
/// the one it is not called for — that is the whole of eliding.
///
/// # What it costs
///
/// Nothing on drafts 07-14, and on drafts 15-21 one header re-derivation per
/// frame, which allocates only when the answer differs from the bytes that
/// arrived. A stream with nothing removed from it therefore forwards every
/// frame's own bytes and copies no payload.
///
/// # Drafts 18 and 19 need the Group Order
///
/// Their Group ID is a difference whose sign the fetch's Group Order decides,
/// exactly as for [`AnyFetchObjectReader`], and it is settled on the control
/// plane rather than on the data stream. [`new`](Self::new) takes it for that
/// reason: the wrong order re-encodes without error onto groups walking the
/// wrong way.
#[derive(Debug, Clone)]
pub struct AnyFetchObjectWriter {
    state: FetchWriterState,
}

impl AnyFetchObjectWriter {
    /// Create a writer for a stream with the given header, whose groups are
    /// written in `group_order`.
    ///
    /// See the type's own documentation for what the order is for and why it
    /// cannot be read off the stream. On drafts 07-17 the argument is ignored.
    ///
    /// Returns [`CodecError::UnsupportedDraft`] for drafts not compiled in.
    #[allow(unused_variables, unreachable_code)]
    pub fn new(
        header: &AnyFetchHeader,
        group_order: AnyFetchGroupOrder,
    ) -> Result<Self, CodecError> {
        let state = match header {
            #[cfg(feature = "draft07")]
            AnyFetchHeader::Draft07(_) => FetchWriterState::Absolute(DraftVersion::Draft07),
            #[cfg(feature = "draft08")]
            AnyFetchHeader::Draft08(_) => FetchWriterState::Absolute(DraftVersion::Draft08),
            #[cfg(feature = "draft09")]
            AnyFetchHeader::Draft09(_) => FetchWriterState::Absolute(DraftVersion::Draft09),
            #[cfg(feature = "draft10")]
            AnyFetchHeader::Draft10(_) => FetchWriterState::Absolute(DraftVersion::Draft10),
            #[cfg(feature = "draft11")]
            AnyFetchHeader::Draft11(_) => FetchWriterState::Absolute(DraftVersion::Draft11),
            #[cfg(feature = "draft12")]
            AnyFetchHeader::Draft12(_) => FetchWriterState::Absolute(DraftVersion::Draft12),
            #[cfg(feature = "draft13")]
            AnyFetchHeader::Draft13(_) => FetchWriterState::Absolute(DraftVersion::Draft13),
            #[cfg(feature = "draft14")]
            AnyFetchHeader::Draft14(_) => FetchWriterState::Absolute(DraftVersion::Draft14),
            #[cfg(feature = "draft15")]
            AnyFetchHeader::Draft15(_) => {
                FetchWriterState::Draft15(crate::draft15::data_stream::FetchObjectWriter::new())
            }
            #[cfg(feature = "draft16")]
            AnyFetchHeader::Draft16(_) => {
                FetchWriterState::Draft16(crate::draft16::data_stream::FetchObjectWriter::new())
            }
            #[cfg(feature = "draft17")]
            AnyFetchHeader::Draft17(_) => {
                FetchWriterState::Draft17(crate::draft17::data_stream::FetchObjectWriter::new())
            }
            #[cfg(feature = "draft18")]
            AnyFetchHeader::Draft18(_) => FetchWriterState::Draft18(
                crate::draft18::data_stream::FetchObjectWriter::new(match group_order {
                    AnyFetchGroupOrder::Ascending => {
                        crate::draft18::data_stream::GroupOrder::Ascending
                    }
                    AnyFetchGroupOrder::Descending => {
                        crate::draft18::data_stream::GroupOrder::Descending
                    }
                }),
            ),
            #[cfg(feature = "draft19")]
            AnyFetchHeader::Draft19(_) => FetchWriterState::Draft19(
                crate::draft19::data_stream::FetchObjectWriter::new(match group_order {
                    AnyFetchGroupOrder::Ascending => {
                        crate::draft19::data_stream::GroupOrder::Ascending
                    }
                    AnyFetchGroupOrder::Descending => {
                        crate::draft19::data_stream::GroupOrder::Descending
                    }
                }),
            ),
            #[cfg(feature = "draft20")]
            AnyFetchHeader::Draft20(_) => FetchWriterState::Draft20(
                crate::draft20::data_stream::FetchObjectWriter::new(match group_order {
                    AnyFetchGroupOrder::Ascending => {
                        crate::draft20::data_stream::GroupOrder::Ascending
                    }
                    AnyFetchGroupOrder::Descending => {
                        crate::draft20::data_stream::GroupOrder::Descending
                    }
                }),
            ),
            #[cfg(feature = "draft21")]
            AnyFetchHeader::Draft21(_) => FetchWriterState::Draft21(
                crate::draft21::data_stream::FetchObjectWriter::new(match group_order {
                    AnyFetchGroupOrder::Ascending => {
                        crate::draft21::data_stream::GroupOrder::Ascending
                    }
                    AnyFetchGroupOrder::Descending => {
                        crate::draft21::data_stream::GroupOrder::Descending
                    }
                }),
            ),
            #[allow(unreachable_patterns)]
            _ => {
                return Err(CodecError::UnsupportedDraft(format!(
                    "draft {:?} not enabled via feature flag",
                    header.draft()
                )));
            }
        };
        Ok(Self { state })
    }

    /// The draft this writer encodes.
    #[must_use]
    #[allow(unreachable_code)]
    pub fn draft(&self) -> DraftVersion {
        match &self.state {
            #[cfg(any(
                feature = "draft07",
                feature = "draft08",
                feature = "draft09",
                feature = "draft10",
                feature = "draft11",
                feature = "draft12",
                feature = "draft13",
                feature = "draft14"
            ))]
            FetchWriterState::Absolute(draft) => *draft,
            #[cfg(feature = "draft15")]
            FetchWriterState::Draft15(_) => DraftVersion::Draft15,
            #[cfg(feature = "draft16")]
            FetchWriterState::Draft16(_) => DraftVersion::Draft16,
            #[cfg(feature = "draft17")]
            FetchWriterState::Draft17(_) => DraftVersion::Draft17,
            #[cfg(feature = "draft18")]
            FetchWriterState::Draft18(_) => DraftVersion::Draft18,
            #[cfg(feature = "draft19")]
            FetchWriterState::Draft19(_) => DraftVersion::Draft19,
            #[cfg(feature = "draft20")]
            FetchWriterState::Draft20(_) => DraftVersion::Draft20,
            #[cfg(feature = "draft21")]
            FetchWriterState::Draft21(_) => DraftVersion::Draft21,
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyFetchObjectWriter has no enabled variants"),
        }
    }

    /// Re-emit one forwarded fetch frame, re-encoding its framing against the
    /// frames actually forwarded before it, and advance.
    ///
    /// `frame` came from [`AnyFetchObjectReader::read_object_frame`] on the
    /// stream being read; `raw` is that frame's wire bytes. The return value
    /// says which bytes to forward, and the two answers are not symmetric:
    /// [`FetchReemit::Unchanged`] writes nothing and means `raw` is still
    /// correct, while [`FetchReemit::Reframed`] has written the whole frame to
    /// `out` and `raw` must not also be forwarded.
    ///
    /// # `raw` need not be a complete frame
    ///
    /// **Any prefix is legal provided the whole framing is present** — the
    /// framing being `meta.wire_len - meta.payload_length` bytes, which is a
    /// number the frame already carries. Everything behind it is copied
    /// byte-for-byte, however many bytes there are, and no length validation is
    /// performed. That is what lets a caller fix up the first chunk of a frame
    /// too large to buffer, where only the first chunk carries the framing at
    /// all.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedDraft`] when `frame` was read off another
    /// draft's stream.
    ///
    /// [`CodecError::InvalidField`] when `raw` is shorter than the framing the
    /// frame declares, and when the frame has no encoding against the
    /// predecessor now in front of it — a Group ID that moves against the
    /// Group Order, an Object ID that does not advance, and the arithmetic
    /// overflows. The writer is left where it was in that case, so a caller
    /// that gives up on one frame and carries on is not also one frame out.
    #[allow(unused_variables)]
    pub fn reemit_object(
        &mut self,
        frame: &AnyFetchFrame,
        raw: &[u8],
        out: &mut impl BufMut,
    ) -> Result<FetchReemit, CodecError> {
        if frame.draft != self.draft() {
            return Err(CodecError::UnsupportedDraft(format!(
                "a draft {:?} fetch frame cannot be written onto a draft {:?} stream",
                frame.draft,
                self.draft()
            )));
        }

        let framing_len = frame.meta.wire_len.saturating_sub(frame.meta.payload_length);
        let framing_len = usize::try_from(framing_len).map_err(|_| CodecError::InvalidField)?;
        if framing_len > raw.len() {
            return Err(CodecError::InvalidField);
        }
        let (framing, rest) = raw.split_at(framing_len);

        match (&mut self.state, &frame.shape) {
            // Nothing on these drafts' wire is written against anything, so
            // the frame's own bytes are correct wherever it lands.
            #[cfg(any(
                feature = "draft07",
                feature = "draft08",
                feature = "draft09",
                feature = "draft10",
                feature = "draft11",
                feature = "draft12",
                feature = "draft13",
                feature = "draft14"
            ))]
            (FetchWriterState::Absolute(_), FetchFrameShape::Absolute) => {
                Ok(FetchReemit::Unchanged)
            }
            #[cfg(feature = "draft15")]
            (FetchWriterState::Draft15(writer), FetchFrameShape::Draft15(original)) => {
                let reframed = writer.header_for(original)?;
                if reframed == *original {
                    writer.advance(original);
                    return Ok(FetchReemit::Unchanged);
                }
                let mut encoded = Vec::with_capacity(framing.len() + 16);
                reframed.encode(&mut encoded)?;
                writer.advance(&reframed);
                Ok(put_reframed(&encoded, framing.len(), rest, out))
            }
            #[cfg(feature = "draft16")]
            (FetchWriterState::Draft16(writer), FetchFrameShape::Draft16(original, location)) => {
                let reframed = writer.header_for(original, location)?;
                if reframed == *original {
                    writer.advance(original, location);
                    return Ok(FetchReemit::Unchanged);
                }
                let mut encoded = Vec::with_capacity(framing.len() + 16);
                reframed.encode(&mut encoded)?;
                writer.advance(&reframed, location);
                Ok(put_reframed(&encoded, framing.len(), rest, out))
            }
            #[cfg(feature = "draft17")]
            (FetchWriterState::Draft17(writer), FetchFrameShape::Draft17(original)) => {
                let reframed = writer.header_for(original)?;
                if reframed == original.header {
                    writer.advance(original);
                    return Ok(FetchReemit::Unchanged);
                }
                let mut encoded = Vec::with_capacity(framing.len() + 16);
                reframed.encode(&mut encoded)?;
                writer.advance(original);
                Ok(put_reframed(&encoded, framing.len(), rest, out))
            }
            #[cfg(feature = "draft18")]
            (FetchWriterState::Draft18(writer), FetchFrameShape::Draft18(original)) => {
                let reframed = writer.header_for(original)?;
                if reframed == original.header {
                    writer.advance(original);
                    return Ok(FetchReemit::Unchanged);
                }
                let mut encoded = Vec::with_capacity(framing.len() + 16);
                reframed.encode(&mut encoded)?;
                writer.advance(original);
                Ok(put_reframed(&encoded, framing.len(), rest, out))
            }
            #[cfg(feature = "draft19")]
            (FetchWriterState::Draft19(writer), FetchFrameShape::Draft19(original)) => {
                let reframed = writer.header_for(original)?;
                if reframed == original.header {
                    writer.advance(original);
                    return Ok(FetchReemit::Unchanged);
                }
                let mut encoded = Vec::with_capacity(framing.len() + 16);
                reframed.encode(&mut encoded)?;
                writer.advance(original);
                Ok(put_reframed(&encoded, framing.len(), rest, out))
            }
            #[cfg(feature = "draft20")]
            (FetchWriterState::Draft20(writer), FetchFrameShape::Draft20(original)) => {
                let reframed = writer.header_for(original)?;
                if reframed == original.header {
                    writer.advance(original);
                    return Ok(FetchReemit::Unchanged);
                }
                let mut encoded = Vec::with_capacity(framing.len() + 16);
                reframed.encode(&mut encoded)?;
                writer.advance(original);
                Ok(put_reframed(&encoded, framing.len(), rest, out))
            }
            #[cfg(feature = "draft21")]
            (FetchWriterState::Draft21(writer), FetchFrameShape::Draft21(original)) => {
                let reframed = writer.header_for(original)?;
                if reframed == original.header {
                    writer.advance(original);
                    return Ok(FetchReemit::Unchanged);
                }
                let mut encoded = Vec::with_capacity(framing.len() + 16);
                reframed.encode(&mut encoded)?;
                writer.advance(original);
                Ok(put_reframed(&encoded, framing.len(), rest, out))
            }
            // Unreachable: the drafts were compared before this match, and one
            // draft has one state and one shape.
            #[allow(unreachable_patterns)]
            _ => Err(CodecError::UnsupportedDraft(format!(
                "no fetch writer for draft {:?}",
                frame.draft
            ))),
        }
    }
}

/// Write a re-encoded frame out: the new framing, then every byte that stood
/// behind the old one.
#[cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
fn put_reframed(
    encoded: &[u8],
    framing_bytes_before: usize,
    rest: &[u8],
    out: &mut impl BufMut,
) -> FetchReemit {
    out.put_slice(encoded);
    out.put_slice(rest);
    FetchReemit::Reframed { framing_bytes_before, framing_bytes_after: encoded.len() }
}

// ── Header helpers for the stream-type-gated drafts ─────────

/// Generates the subgroup stream-type check drafts 11-13 share: the header's
/// stream type must be a subgroup type, and it decides whether objects carry
/// an extension block.
macro_rules! subgroup_extensions_fn {
    ($name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        fn $name(header: &crate::$draft::data_stream::SubgroupHeader) -> Result<bool, CodecError> {
            if !header.stream_type.is_subgroup() {
                return Err(CodecError::InvalidField);
            }
            Ok(header.stream_type.has_extensions())
        }
    };
}

subgroup_extensions_fn!(subgroup_extensions_11, "draft11", draft11);
subgroup_extensions_fn!(subgroup_extensions_12, "draft12", draft12);
subgroup_extensions_fn!(subgroup_extensions_13, "draft13", draft13);

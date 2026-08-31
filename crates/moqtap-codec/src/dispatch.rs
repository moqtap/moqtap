//! Unified types and version-aware decode/encode for runtime draft dispatch.
//!
//! This module provides wrapper enums (`Any*`) that hold any enabled draft's
//! types and dispatch encoding/decoding based on
//! [`DraftVersion`](crate::version::DraftVersion).
//!
//! Each enum variant is gated on its draft feature flag. Enable multiple draft
//! features (e.g. `draft07` + `draft14`) for runtime dispatch between drafts.

use bytes::{Buf, BufMut};

use crate::error::CodecError;
use crate::version::DraftVersion;

pub use crate::data_dispatch::{
    reemit_subgroup_object, AnyFetchEndOfRange, AnyFetchFrame, AnyFetchGroupOrder, AnyFetchObject,
    AnyFetchObjectMeta, AnyFetchObjectReader, AnyFetchObjectWriter, AnySubgroupObject,
    AnySubgroupObjectMeta, AnySubgroupObjectReader, AnySubgroupObjectWriter, FetchReemit, Reemit,
};

/// Generates a dispatch enum with one variant per enabled draft feature.
///
/// Each variant wraps the draft-specific type and delegates encode/decode
/// to the appropriate draft module.
macro_rules! dispatch_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                #[cfg(feature = $feat:literal)]
                $variant:ident => $module:path,
            )+
        }
        decode($decode_fn:ident);
        encode($encode_fn:ident -> $encode_ret:ty);
    ) => {
        $(#[$meta])*
        $vis enum $name {
            $(
                #[cfg(feature = $feat)]
                #[doc = concat!("Draft-", $feat, " variant.")]
                $variant($module),
            )+
        }

        impl $name {
            /// Decode from wire using the specified draft version.
            #[allow(unused_variables)]
            pub fn decode(
                version: DraftVersion,
                buf: &mut impl Buf,
            ) -> Result<Self, CodecError> {
                match version {
                    $(
                        #[cfg(feature = $feat)]
                        DraftVersion::$variant => {
                            <$module>::$decode_fn(buf).map($name::$variant)
                        }
                    )+
                    #[allow(unreachable_patterns)]
                    _ => Err(CodecError::UnsupportedDraft(
                        format!("draft {:?} not enabled via feature flag", version),
                    )),
                }
            }

            /// Encode to wire using the appropriate draft's format.
            #[allow(unused_variables, unreachable_code)]
            pub fn encode(&self, buf: &mut impl BufMut) -> $encode_ret {
                match self {
                    $(
                        #[cfg(feature = $feat)]
                        $name::$variant(inner) => inner.$encode_fn(buf),
                    )+
                    #[allow(unreachable_patterns)]
                    _ => unreachable!("AnyXxx enum has no enabled variants"),
                }
            }

            /// Returns the draft version this value belongs to.
            #[allow(unreachable_code)]
            pub fn draft(&self) -> DraftVersion {
                match self {
                    $(
                        #[cfg(feature = $feat)]
                        $name::$variant(_) => DraftVersion::$variant,
                    )+
                    #[allow(unreachable_patterns)]
                    _ => unreachable!("AnyXxx enum has no enabled variants"),
                }
            }
        }
    };
}

/// Generates one uniform [`AnySubgroupHeader`] accessor.
///
/// Bodies are written once per group of drafts that share one; every arm is
/// `#[cfg]`-gated on its own draft feature and a catch-all closes the match,
/// so a single-draft build and a zero-draft build both compile — the same
/// shape [`dispatch_enum!`] generates for `draft()`.
macro_rules! subgroup_header_accessor {
    (
        $(#[$meta:meta])*
        $name:ident -> $ret:ty;
        $(
            [ $( $variant:ident @ $feat:literal ),+ $(,)? ] => |$h:ident| $body:expr
        ),+ $(,)?
    ) => {
        $(#[$meta])*
        #[allow(unreachable_code)]
        pub fn $name(&self) -> $ret {
            match self {
                $($(
                    #[cfg(feature = $feat)]
                    AnySubgroupHeader::$variant($h) => $body,
                )+)+
                #[allow(unreachable_patterns)]
                _ => unreachable!("AnySubgroupHeader has no enabled variants"),
            }
        }
    };
}

// ── Control messages ────────────────────────────────────────

dispatch_enum! {
    /// A control message from any enabled draft.
    #[derive(Debug, Clone)]
    pub enum AnyControlMessage {
        #[cfg(feature = "draft07")]
        Draft07 => crate::draft07::message::ControlMessage,
        #[cfg(feature = "draft08")]
        Draft08 => crate::draft08::message::ControlMessage,
        #[cfg(feature = "draft09")]
        Draft09 => crate::draft09::message::ControlMessage,
        #[cfg(feature = "draft10")]
        Draft10 => crate::draft10::message::ControlMessage,
        #[cfg(feature = "draft11")]
        Draft11 => crate::draft11::message::ControlMessage,
        #[cfg(feature = "draft12")]
        Draft12 => crate::draft12::message::ControlMessage,
        #[cfg(feature = "draft13")]
        Draft13 => crate::draft13::message::ControlMessage,
        #[cfg(feature = "draft14")]
        Draft14 => crate::draft14::message::ControlMessage,
        #[cfg(feature = "draft15")]
        Draft15 => crate::draft15::message::ControlMessage,
        #[cfg(feature = "draft16")]
        Draft16 => crate::draft16::message::ControlMessage,
        #[cfg(feature = "draft17")]
        Draft17 => crate::draft17::message::ControlMessage,
        #[cfg(feature = "draft18")]
        Draft18 => crate::draft18::message::ControlMessage,
        #[cfg(feature = "draft19")]
        Draft19 => crate::draft19::message::ControlMessage,
    }
    decode(decode);
    encode(encode -> Result<(), CodecError>);
}

impl AnyControlMessage {
    /// Returns `true` if this is a CLIENT_SETUP or SERVER_SETUP message.
    pub fn is_setup(&self) -> bool {
        match self {
            #[cfg(feature = "draft07")]
            AnyControlMessage::Draft07(m) => matches!(
                m,
                crate::draft07::message::ControlMessage::ClientSetup(_)
                    | crate::draft07::message::ControlMessage::ServerSetup(_)
            ),
            #[cfg(feature = "draft08")]
            AnyControlMessage::Draft08(m) => matches!(
                m,
                crate::draft08::message::ControlMessage::ClientSetup(_)
                    | crate::draft08::message::ControlMessage::ServerSetup(_)
            ),
            #[cfg(feature = "draft09")]
            AnyControlMessage::Draft09(m) => matches!(
                m,
                crate::draft09::message::ControlMessage::ClientSetup(_)
                    | crate::draft09::message::ControlMessage::ServerSetup(_)
            ),
            #[cfg(feature = "draft10")]
            AnyControlMessage::Draft10(m) => matches!(
                m,
                crate::draft10::message::ControlMessage::ClientSetup(_)
                    | crate::draft10::message::ControlMessage::ServerSetup(_)
            ),
            #[cfg(feature = "draft11")]
            AnyControlMessage::Draft11(m) => matches!(
                m,
                crate::draft11::message::ControlMessage::ClientSetup(_)
                    | crate::draft11::message::ControlMessage::ServerSetup(_)
            ),
            #[cfg(feature = "draft12")]
            AnyControlMessage::Draft12(m) => matches!(
                m,
                crate::draft12::message::ControlMessage::ClientSetup(_)
                    | crate::draft12::message::ControlMessage::ServerSetup(_)
            ),
            #[cfg(feature = "draft13")]
            AnyControlMessage::Draft13(m) => matches!(
                m,
                crate::draft13::message::ControlMessage::ClientSetup(_)
                    | crate::draft13::message::ControlMessage::ServerSetup(_)
            ),
            #[cfg(feature = "draft14")]
            AnyControlMessage::Draft14(m) => matches!(
                m,
                crate::draft14::message::ControlMessage::ClientSetup(_)
                    | crate::draft14::message::ControlMessage::ServerSetup(_)
            ),
            #[cfg(feature = "draft15")]
            AnyControlMessage::Draft15(m) => matches!(
                m,
                crate::draft15::message::ControlMessage::ClientSetup(_)
                    | crate::draft15::message::ControlMessage::ServerSetup(_)
            ),
            #[cfg(feature = "draft16")]
            AnyControlMessage::Draft16(m) => matches!(
                m,
                crate::draft16::message::ControlMessage::ClientSetup(_)
                    | crate::draft16::message::ControlMessage::ServerSetup(_)
            ),
            #[cfg(feature = "draft17")]
            AnyControlMessage::Draft17(m) => {
                matches!(m, crate::draft17::message::ControlMessage::Setup(_))
            }
            #[cfg(feature = "draft18")]
            AnyControlMessage::Draft18(m) => {
                matches!(m, crate::draft18::message::ControlMessage::Setup(_))
            }
            #[cfg(feature = "draft19")]
            AnyControlMessage::Draft19(m) => {
                matches!(m, crate::draft19::message::ControlMessage::Setup(_))
            }
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// The Request ID and Group Order of a FETCH, on the drafts where the
    /// FETCH settles the order by itself.
    ///
    /// A fetch response's Objects arrive in the order the request asked for.
    /// Draft-19 Section 10.12.3: "The publisher responding to a FETCH is
    /// responsible for delivering all available Objects in the requested
    /// range in the requested order (see Section 10.2.8)." Draft-19 Section
    /// 10.2.8 carries the order itself, as the GROUP_ORDER parameter, and states
    /// what its absence means: "If omitted from FETCH, the receiver uses
    /// Ascending (0x1)." So on those drafts one message answers the question
    /// outright, whether or not it carries the parameter, and that is what
    /// this returns.
    ///
    /// The answer matters most on drafts 18 and 19, whose fetch Objects write
    /// a Group ID as a difference from the Object before and leave the order
    /// to decide its sign — see
    /// [`AnyFetchObjectReader::new`]. Drafts 15, 16 and 17
    /// state the same rule about the same parameter and their fetch streams
    /// resolve without it, so this answers for them too rather than for the
    /// two that happen to need it.
    ///
    /// # What answers `None`
    ///
    /// Any message that is not a FETCH, and **every FETCH on drafts 07-14**.
    /// Those drafts carry Group Order as a field of the FETCH rather than as
    /// a parameter, and its value 0x0 means the subscriber expressed no
    /// preference — which leaves the order to the publisher, who states it in
    /// the FETCH_OK. That is a two-message negotiation, and a function handed
    /// one message cannot answer it. Answering Ascending there would be a
    /// guess wearing the same return type as a fact.
    ///
    /// Also `None` for a GROUP_ORDER value that is neither Ascending (0x1)
    /// nor Descending (0x2), which drafts 15-19 make a session-closing
    /// PROTOCOL_VIOLATION and this crate's decoder refuses before building a
    /// message. Defensive, and deliberately not the Ascending default: an
    /// out-of-range value is not an omitted one.
    #[allow(unreachable_patterns, unused_variables)]
    pub fn fetch_group_order(&self) -> Option<(u64, AnyFetchGroupOrder)> {
        /// GROUP_ORDER, Parameter Type 0x22 on every draft that has it.
        ///
        /// Both of these go unused in a build compiling none of drafts 15-19,
        /// which is the honest report: no draft in such a build carries a
        /// fetch's Group Order as a parameter, so every arm below is gated
        /// out and the match is the `None` arm alone.
        #[allow(dead_code)]
        const GROUP_ORDER: u64 = 0x22;

        #[allow(dead_code)]
        fn fetch_group_order(
            request_id: crate::varint::VarInt,
            parameters: &[crate::kvp::KeyValuePair],
        ) -> Option<(u64, AnyFetchGroupOrder)> {
            // The first, because drafts 15-19 refuse a repeated parameter
            // before a message is built, so there is never a second.
            let order = match parameters.iter().find(|p| p.key.into_inner() == GROUP_ORDER) {
                None => AnyFetchGroupOrder::Ascending,
                Some(p) => match &p.value {
                    crate::kvp::KvpValue::Varint(v) => match v.into_inner() {
                        0x1 => AnyFetchGroupOrder::Ascending,
                        0x2 => AnyFetchGroupOrder::Descending,
                        _ => return None,
                    },
                    // An even key type carries a varint, so this shape does
                    // not survive decoding either.
                    crate::kvp::KvpValue::Bytes(_) => return None,
                },
            };
            Some((request_id.into_inner(), order))
        }

        match self {
            #[cfg(feature = "draft15")]
            AnyControlMessage::Draft15(crate::draft15::message::ControlMessage::Fetch(f)) => {
                fetch_group_order(f.request_id, &f.parameters)
            }
            #[cfg(feature = "draft16")]
            AnyControlMessage::Draft16(crate::draft16::message::ControlMessage::Fetch(f)) => {
                fetch_group_order(f.request_id, &f.parameters)
            }
            #[cfg(feature = "draft17")]
            AnyControlMessage::Draft17(crate::draft17::message::ControlMessage::Fetch(f)) => {
                fetch_group_order(f.request_id, &f.parameters)
            }
            #[cfg(feature = "draft18")]
            AnyControlMessage::Draft18(crate::draft18::message::ControlMessage::Fetch(f)) => {
                fetch_group_order(f.request_id, &f.parameters)
            }
            #[cfg(feature = "draft19")]
            AnyControlMessage::Draft19(crate::draft19::message::ControlMessage::Fetch(f)) => {
                fetch_group_order(f.request_id, &f.parameters)
            }
            _ => None,
        }
    }
}

// ── Data stream headers ─────────────────────────────────────

dispatch_enum! {
    /// A subgroup header from any enabled draft.
    #[derive(Debug, Clone)]
    pub enum AnySubgroupHeader {
        #[cfg(feature = "draft07")]
        Draft07 => crate::draft07::data_stream::SubgroupHeader,
        #[cfg(feature = "draft08")]
        Draft08 => crate::draft08::data_stream::SubgroupHeader,
        #[cfg(feature = "draft09")]
        Draft09 => crate::draft09::data_stream::SubgroupHeader,
        #[cfg(feature = "draft10")]
        Draft10 => crate::draft10::data_stream::SubgroupHeader,
        #[cfg(feature = "draft11")]
        Draft11 => crate::draft11::data_stream::SubgroupHeader,
        #[cfg(feature = "draft12")]
        Draft12 => crate::draft12::data_stream::SubgroupHeader,
        #[cfg(feature = "draft13")]
        Draft13 => crate::draft13::data_stream::SubgroupHeader,
        #[cfg(feature = "draft14")]
        Draft14 => crate::draft14::data_stream::SubgroupHeader,
        #[cfg(feature = "draft15")]
        Draft15 => crate::draft15::data_stream::SubgroupHeader,
        #[cfg(feature = "draft16")]
        Draft16 => crate::draft16::data_stream::SubgroupHeader,
        #[cfg(feature = "draft17")]
        Draft17 => crate::draft17::data_stream::SubgroupHeader,
        #[cfg(feature = "draft18")]
        Draft18 => crate::draft18::data_stream::SubgroupHeader,
        #[cfg(feature = "draft19")]
        Draft19 => crate::draft19::data_stream::SubgroupHeader,
    }
    decode(decode);
    encode(encode -> ());
}

impl AnySubgroupHeader {
    /// Decode a subgroup stream header including its leading stream-type
    /// field, for any enabled draft.
    ///
    /// Drafts 07-13 encode the stream type as a varint ahead of the header
    /// body; drafts 14-19 fold it into the header itself. This entry point
    /// hides that difference: callers hand it the stream's first byte onwards
    /// and it consumes exactly the header, type field included.
    ///
    /// On drafts 11-13 the stream type also selects the header layout and
    /// fixes whether objects carry extension headers, which
    /// [`Self::decode`] cannot know; prefer this entry point whenever the
    /// stream's first byte is available.
    #[allow(unused_variables)]
    pub fn decode_stream(version: DraftVersion, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match version {
            #[cfg(feature = "draft07")]
            DraftVersion::Draft07 => {
                crate::draft07::data_stream::SubgroupHeader::decode_stream(buf)
                    .map(AnySubgroupHeader::Draft07)
            }
            #[cfg(feature = "draft08")]
            DraftVersion::Draft08 => {
                crate::draft08::data_stream::SubgroupHeader::decode_stream(buf)
                    .map(AnySubgroupHeader::Draft08)
            }
            #[cfg(feature = "draft09")]
            DraftVersion::Draft09 => {
                crate::draft09::data_stream::SubgroupHeader::decode_stream(buf)
                    .map(AnySubgroupHeader::Draft09)
            }
            #[cfg(feature = "draft10")]
            DraftVersion::Draft10 => {
                crate::draft10::data_stream::SubgroupHeader::decode_stream(buf)
                    .map(AnySubgroupHeader::Draft10)
            }
            #[cfg(feature = "draft11")]
            DraftVersion::Draft11 => {
                crate::draft11::data_stream::SubgroupHeader::decode_stream(buf)
                    .map(AnySubgroupHeader::Draft11)
            }
            #[cfg(feature = "draft12")]
            DraftVersion::Draft12 => {
                crate::draft12::data_stream::SubgroupHeader::decode_stream(buf)
                    .map(AnySubgroupHeader::Draft12)
            }
            #[cfg(feature = "draft13")]
            DraftVersion::Draft13 => {
                crate::draft13::data_stream::SubgroupHeader::decode_stream(buf)
                    .map(AnySubgroupHeader::Draft13)
            }
            #[cfg(feature = "draft14")]
            DraftVersion::Draft14 => crate::draft14::data_stream::SubgroupHeader::decode(buf)
                .map(AnySubgroupHeader::Draft14),
            #[cfg(feature = "draft15")]
            DraftVersion::Draft15 => crate::draft15::data_stream::SubgroupHeader::decode(buf)
                .map(AnySubgroupHeader::Draft15),
            #[cfg(feature = "draft16")]
            DraftVersion::Draft16 => crate::draft16::data_stream::SubgroupHeader::decode(buf)
                .map(AnySubgroupHeader::Draft16),
            #[cfg(feature = "draft17")]
            DraftVersion::Draft17 => crate::draft17::data_stream::SubgroupHeader::decode(buf)
                .map(AnySubgroupHeader::Draft17),
            #[cfg(feature = "draft18")]
            DraftVersion::Draft18 => crate::draft18::data_stream::SubgroupHeader::decode(buf)
                .map(AnySubgroupHeader::Draft18),
            #[cfg(feature = "draft19")]
            DraftVersion::Draft19 => crate::draft19::data_stream::SubgroupHeader::decode(buf)
                .map(AnySubgroupHeader::Draft19),
            #[allow(unreachable_patterns)]
            _ => Err(CodecError::UnsupportedDraft(format!(
                "draft {version:?} not enabled via feature flag"
            ))),
        }
    }

    /// Encode a subgroup stream header including its leading stream-type
    /// field, the inverse of [`Self::decode_stream`].
    ///
    /// [`Self::encode`] is not that inverse on drafts 07-13 and never was:
    /// it writes the header body alone, so bytes written with it and read
    /// back with [`Self::decode_stream`] lose their first field and shift
    /// every field after it. Use this for a stream's first write and
    /// [`Self::encode`] only once the stream is already open.
    // A build with no draft feature compiles this match to no arms at all,
    // which leaves the parameter read by nothing. That is the same shape
    // `unreachable_code` is allowed for here, and it is a real configuration
    // — CI checks it — rather than a hypothetical one.
    #[allow(unreachable_code, unused_variables)]
    pub fn encode_stream(&self, buf: &mut impl BufMut) {
        match self {
            #[cfg(feature = "draft07")]
            AnySubgroupHeader::Draft07(h) => h.encode_stream(buf),
            #[cfg(feature = "draft08")]
            AnySubgroupHeader::Draft08(h) => h.encode_stream(buf),
            #[cfg(feature = "draft09")]
            AnySubgroupHeader::Draft09(h) => h.encode_stream(buf),
            #[cfg(feature = "draft10")]
            AnySubgroupHeader::Draft10(h) => h.encode_stream(buf),
            #[cfg(feature = "draft11")]
            AnySubgroupHeader::Draft11(h) => h.encode_stream(buf),
            #[cfg(feature = "draft12")]
            AnySubgroupHeader::Draft12(h) => h.encode_stream(buf),
            #[cfg(feature = "draft13")]
            AnySubgroupHeader::Draft13(h) => h.encode_stream(buf),
            // Drafts 14-19 fold the stream type into the header, so their
            // `encode` already writes it and `decode_stream` already reads
            // it back.
            #[cfg(feature = "draft14")]
            AnySubgroupHeader::Draft14(h) => h.encode(buf),
            #[cfg(feature = "draft15")]
            AnySubgroupHeader::Draft15(h) => h.encode(buf),
            #[cfg(feature = "draft16")]
            AnySubgroupHeader::Draft16(h) => h.encode(buf),
            #[cfg(feature = "draft17")]
            AnySubgroupHeader::Draft17(h) => h.encode(buf),
            #[cfg(feature = "draft18")]
            AnySubgroupHeader::Draft18(h) => h.encode(buf),
            #[cfg(feature = "draft19")]
            AnySubgroupHeader::Draft19(h) => h.encode(buf),
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnySubgroupHeader has no enabled variants"),
        }
    }

    /// Encode the header body, refusing a value the stream type will not carry,
    /// and write the type field in front of it.
    ///
    /// The checked form of [`Self::encode_stream`]. Every draft from 11 on has
    /// a header type table with a column the value can disagree with - a
    /// Subgroup ID the type does not write, an `Option` that does not match
    /// what the type says is present - and disagreeing does not produce a
    /// malformed stream. It produces a well-formed stream for a different
    /// subgroup, or with a different priority, which the peer has no way to
    /// question. Each draft's own `encode_checked` says no to that; this is the
    /// one entry point that reaches all of them.
    ///
    /// Drafts 07 through 10 have nothing to refuse: their SUBGROUP_HEADER has
    /// one shape, every field is written every time, and no type byte selects
    /// between them. They are written unchanged.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] if the header's fields disagree with its
    /// own type. A refused header leaves `buf` untouched.
    #[allow(unreachable_code, unused_variables, unused_mut)]
    pub fn encode_stream_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let mut body = Vec::with_capacity(32);
        match self {
            #[cfg(feature = "draft07")]
            AnySubgroupHeader::Draft07(h) => h.encode_stream(&mut body),
            #[cfg(feature = "draft08")]
            AnySubgroupHeader::Draft08(h) => h.encode_stream(&mut body),
            #[cfg(feature = "draft09")]
            AnySubgroupHeader::Draft09(h) => h.encode_stream(&mut body),
            #[cfg(feature = "draft10")]
            AnySubgroupHeader::Draft10(h) => h.encode_stream(&mut body),
            // Drafts 11-13 write the stream type ahead of a body their
            // `encode_checked` produces on its own.
            #[cfg(feature = "draft11")]
            AnySubgroupHeader::Draft11(h) => {
                crate::varint::VarInt::from_usize(h.stream_type as usize).encode(&mut body);
                h.encode_checked(&mut body)?;
            }
            #[cfg(feature = "draft12")]
            AnySubgroupHeader::Draft12(h) => {
                crate::varint::VarInt::from_usize(h.stream_type as usize).encode(&mut body);
                h.encode_checked(&mut body)?;
            }
            #[cfg(feature = "draft13")]
            AnySubgroupHeader::Draft13(h) => {
                crate::varint::VarInt::from_usize(h.stream_type as usize).encode(&mut body);
                h.encode_checked(&mut body)?;
            }
            // Drafts 14-19 fold the type into the header, so their
            // `encode_checked` already writes it.
            #[cfg(feature = "draft14")]
            AnySubgroupHeader::Draft14(h) => h.encode_checked(&mut body)?,
            #[cfg(feature = "draft15")]
            AnySubgroupHeader::Draft15(h) => h.encode_checked(&mut body)?,
            #[cfg(feature = "draft16")]
            AnySubgroupHeader::Draft16(h) => h.encode_checked(&mut body)?,
            #[cfg(feature = "draft17")]
            AnySubgroupHeader::Draft17(h) => h.encode_checked(&mut body)?,
            #[cfg(feature = "draft18")]
            AnySubgroupHeader::Draft18(h) => h.encode_checked(&mut body)?,
            #[cfg(feature = "draft19")]
            AnySubgroupHeader::Draft19(h) => h.encode_checked(&mut body)?,
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnySubgroupHeader has no enabled variants"),
        }
        buf.put_slice(&body);
        Ok(())
    }

    subgroup_header_accessor! {
        /// The Track Alias every object on this stream belongs to.
        track_alias -> u64;
        [
            Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
            Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
            Draft13 @ "draft13", Draft14 @ "draft14", Draft15 @ "draft15",
            Draft16 @ "draft16", Draft17 @ "draft17", Draft18 @ "draft18",
            Draft19 @ "draft19",
        ] => |h| h.track_alias.into_inner(),
    }

    subgroup_header_accessor! {
        /// The Group ID every object on this stream belongs to.
        group_id -> u64;
        [
            Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
            Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
            Draft13 @ "draft13", Draft14 @ "draft14", Draft15 @ "draft15",
            Draft16 @ "draft16", Draft17 @ "draft17", Draft18 @ "draft18",
            Draft19 @ "draft19",
        ] => |h| h.group_id.into_inner(),
    }

    subgroup_header_accessor! {
        /// The Publisher Priority, or `None` when the header set a
        /// default-priority flag and omitted the field (drafts 15+).
        publisher_priority -> Option<u8>;
        [
            Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
            Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
            Draft13 @ "draft13", Draft14 @ "draft14",
        ] => |h| Some(h.publisher_priority),
        [
            Draft15 @ "draft15", Draft16 @ "draft16", Draft17 @ "draft17",
            Draft18 @ "draft18", Draft19 @ "draft19",
        ] => |h| h.publisher_priority,
    }

    subgroup_header_accessor! {
        /// The Subgroup ID this header fixes for its objects, or `None` when
        /// the header does not determine one.
        ///
        /// `None` covers two cases. The first is the *subgroup ID is the first
        /// object's ID* stream, which **every draft from 11 on** defines and
        /// this codec never resolves — nine of the thirteen, not the eight
        /// this said, and the miscount is worth naming because draft-15 spent
        /// a long time excluded from lists elsewhere on exactly that reading.
        /// The second is a header whose type the draft does not assign at all:
        /// drafts 17-19 mode 3, and the same fourth combination of the `0x06`
        /// bits on drafts 15 and 16. In every one of them the codec stores a
        /// placeholder zero that a caller must not report.
        ///
        /// Imposes draft-14's `!has_subgroup_id_field()` guard uniformly. Every
        /// per-draft accessor it reaches through now reads the Subgroup ID
        /// carrier the way that draft's own decoder does, so there is no longer
        /// a disagreement here for this accessor to paper over. Draft-16 used to
        /// read its two mode bits one at a time and so reported a first-object
        /// carrier for a Type whose mode is reserved, which made reaching for
        /// its per-draft accessor directly a way to resolve such a header to the
        /// wrong subgroup.
        subgroup_id -> Option<u64>;
        [
            Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
            Draft10 @ "draft10",
        ] => |h| Some(h.subgroup_id.into_inner()),
        [Draft11 @ "draft11"] => |h| {
            use crate::draft11::data_stream::StreamType;
            match h.stream_type {
                StreamType::SubgroupFirstObj | StreamType::SubgroupFirstObjExt => None,
                _ => Some(h.subgroup_id.into_inner()),
            }
        },
        [Draft12 @ "draft12"] => |h| {
            use crate::draft12::data_stream::StreamType;
            match h.stream_type {
                StreamType::SubgroupFirstObj
                | StreamType::SubgroupFirstObjExt
                | StreamType::SubgroupFirstObjEog
                | StreamType::SubgroupFirstObjEogExt => None,
                _ => Some(h.subgroup_id.into_inner()),
            }
        },
        [Draft13 @ "draft13"] => |h| {
            use crate::draft13::data_stream::StreamType;
            match h.stream_type {
                StreamType::SubgroupFirstObj
                | StreamType::SubgroupFirstObjExt
                | StreamType::SubgroupFirstObjEog
                | StreamType::SubgroupFirstObjEogExt => None,
                _ => Some(h.subgroup_id.into_inner()),
            }
        },
        [Draft14 @ "draft14"] => |h| {
            if h.stream_type.has_subgroup_id_field() {
                Some(h.subgroup_id.map_or(0, |id| id.into_inner()))
            } else if h.stream_type.subgroup_id_is_first_object() {
                None
            } else {
                Some(0)
            }
        },
        // Drafts 15 and 16 read the same three carriers out of the same two
        // bits, so they share an answer — draft-16 naming them a
        // SUBGROUP_ID_MODE and draft-15 giving them as a pair of table
        // columns, which is a difference in wording and not in bytes.
        //
        // `None` is the first-object carrier: the ID is not on the wire and
        // only the stream reader, which has seen the first object, can supply
        // it. Answering `Some(0)` there — which the draft-15 arm used to do —
        // collapses every first-object subgroup onto subgroup zero, and two
        // subgroups of one group must never share a stream.
        //
        // `None` is also the fourth combination, which neither draft assigns:
        // draft-16 reserves those type values by name, draft-15 reaches the
        // same eight by leaving them out of Table 6. No such header decodes,
        // so reaching this arm with one means a caller built it rather than
        // read it, and that caller is the one this accessor exists to protect.
        // `Some(0)` would hand it subgroup zero for a stream no draft defines;
        // `None` says the header determines no Subgroup ID, which is true.
        // Drafts 17-19 already answer `None` for their mode 3, so this is the
        // same rule stated once for all five.
        [Draft15 @ "draft15", Draft16 @ "draft16"] => |h| {
            // The unassigned combination has to be tested somewhere. With the
            // mode reserved neither carrier predicate answers `true`, so the
            // fall-through would report subgroup zero for a stream no draft
            // defines. It is tested first for legibility only: the ordering was
            // load-bearing while draft-16 read its two mode bits one at a time
            // and claimed an explicit Subgroup ID here, and is not any more.
            if h.header_type & 0x06 == 0x06 {
                None
            } else if h.has_explicit_subgroup_id() {
                Some(h.subgroup_id.into_inner())
            } else if h.subgroup_id_from_first_object() {
                None
            } else {
                Some(0)
            }
        },
        [Draft17 @ "draft17", Draft18 @ "draft18", Draft19 @ "draft19"] => |h| {
            match h.subgroup_id_mode() {
                0 => Some(0),
                2 => Some(h.subgroup_id.into_inner()),
                // Mode 1 is *the first object's ID* and mode 3 is reserved; the
                // decoder stores a placeholder zero for each.
                _ => None,
            }
        },
    }

    subgroup_header_accessor! {
        /// The two-bit subgroup-ID mode, on the five drafts that put one in
        /// the header type, or `None` on the eight that do not.
        ///
        /// `0` = the header carries no subgroup ID and it is zero; `1` = the
        /// subgroup ID is the first object's ID; `2` = an explicit ID
        /// follows; `3` = the fourth combination, which no draft assigns.
        ///
        /// Exists because on those five drafts [`Self::subgroup_id`] returns
        /// `None` for **both** mode 1 and mode 3 — the decoder stores a
        /// placeholder zero for each — and the two mean different things to a
        /// caller deciding whether an object may be elided. Without it,
        /// eliding index 0 of a reserved-mode stream is indistinguishable
        /// from eliding it on a stream whose subgroup ID the first object
        /// defines.
        ///
        /// **Reported wherever that ambiguity exists, and that is what picks
        /// the five.** Drafts 16 through 19 name a SUBGROUP_ID_MODE field;
        /// draft-15 does not, and spells the same three carriers out as a
        /// Subgroup ID Field Present column beside a Subgroup ID Value one,
        /// reaching the fourth combination by leaving it out of the table
        /// rather than by reserving it. That is a difference in wording and
        /// not in bytes — same mask, same shift, same four values — so the
        /// question this accessor asks has one answer on both. It is named
        /// for the question and not for any draft's field, as
        /// [`Self::carries_extension_block`] is, and answering it here adds
        /// nothing to `draft15`, which goes on describing its own bits in its
        /// own words.
        ///
        /// `None` on drafts 07 through 14 means the ambiguity is absent, not
        /// the carrier. Drafts 07-10 always put the subgroup ID on the wire.
        /// Drafts 11 through 14 give each carrier a stream type of its own and
        /// assign every type they define, so [`Self::subgroup_id`] answers
        /// `None` for the first-object carrier and for nothing else, and there
        /// is no second reading for a mode to resolve.
        subgroup_id_mode -> Option<u8>;
        [
            Draft07 @ "draft07", Draft08 @ "draft08", Draft09 @ "draft09",
            Draft10 @ "draft10", Draft11 @ "draft11", Draft12 @ "draft12",
            Draft13 @ "draft13", Draft14 @ "draft14",
        ] => |_h| None,
        // Read off the type byte rather than through a per-draft accessor.
        // Draft-15 has no name for the field and gains no method for one;
        // draft-16's would have exactly this caller. The mask is the same
        // literal the arm two accessors above tests, and both headers expose
        // `header_type` directly.
        [Draft15 @ "draft15", Draft16 @ "draft16"] => |h| {
            Some((h.header_type & 0x06) >> 1)
        },
        [Draft17 @ "draft17", Draft18 @ "draft18", Draft19 @ "draft19"] => |h| {
            Some(h.subgroup_id_mode())
        },
    }

    subgroup_header_accessor! {
        /// Whether every object on this stream writes a length-prefixed
        /// extension block — the field drafts 17-19 renamed Properties.
        ///
        /// A property of the *stream*, not of any object on it. The header's
        /// type settles it once, and an object with nothing to put in the
        /// block still writes a length of zero on a stream that carries one.
        /// So a writer cannot work the answer out from the object in its hand,
        /// and one that guesses puts a stream on the wire that no reader can
        /// follow: the missing length is read out of the next field along, and
        /// every object after it is misframed.
        ///
        /// Answered `false` on draft-07, which has no such block at all, and
        /// `true` on drafts 08 through 10, where every object carries one and
        /// no header type can say otherwise. From draft-11 on it is the
        /// header's own answer.
        ///
        /// Exists because nothing else exposed it. `subgroup_id` and
        /// `publisher_priority` report what the header *holds*; this reports
        /// what the objects after it must *write*, and only the first kind was
        /// reachable without matching on the concrete per-draft variant.
        carries_extension_block -> bool;
        [Draft07 @ "draft07"] => |_h| false,
        [Draft08 @ "draft08", Draft09 @ "draft09", Draft10 @ "draft10"] => |_h| true,
        [Draft11 @ "draft11", Draft12 @ "draft12", Draft13 @ "draft13"] => |h| {
            h.stream_type.has_extensions()
        },
        [Draft14 @ "draft14"] => |h| h.stream_type.extensions_present(),
        [Draft15 @ "draft15", Draft16 @ "draft16"] => |h| h.has_extensions(),
        [Draft17 @ "draft17", Draft18 @ "draft18", Draft19 @ "draft19"] => |h| {
            h.has_properties()
        },
    }
}

dispatch_enum! {
    /// An object header from any enabled draft.
    #[derive(Debug, Clone)]
    pub enum AnyObjectHeader {
        #[cfg(feature = "draft07")]
        Draft07 => crate::draft07::data_stream::ObjectHeader,
        #[cfg(feature = "draft08")]
        Draft08 => crate::draft08::data_stream::ObjectHeader,
        #[cfg(feature = "draft09")]
        Draft09 => crate::draft09::data_stream::ObjectHeader,
        #[cfg(feature = "draft10")]
        Draft10 => crate::draft10::data_stream::ObjectHeader,
        #[cfg(feature = "draft11")]
        Draft11 => crate::draft11::data_stream::ObjectHeader,
        #[cfg(feature = "draft12")]
        Draft12 => crate::draft12::data_stream::ObjectHeader,
        #[cfg(feature = "draft13")]
        Draft13 => crate::draft13::data_stream::ObjectHeader,
        // NOTE: drafts 14-19 have no standalone ObjectHeader — their
        // subgroup objects are delta-encoded against the previous object
        // on the stream. Use [`AnySubgroupObjectReader`], which covers
        // every draft 07-19 and also consumes object payloads.
    }
    decode(decode);
    encode(encode -> ());
}

dispatch_enum! {
    /// A datagram header from any enabled draft.
    ///
    /// [`encode`](Self::encode) is fallible on every draft. It dispatches to
    /// each draft's `DatagramHeader::encode_checked` (draft-14's
    /// `DatagramObject::encode_checked`), which refuses a header whose Object
    /// Status the framing it names cannot carry rather than writing the bytes
    /// and dropping the status. Every draft 07-18 says "Any object with a
    /// status code other than zero MUST have an empty payload"; draft-19
    /// replaces that blanket rule with a per-status Payload column in the
    /// Object Status registry of its Section 15.9. Either way there is no
    /// datagram that states End of Group and carries a payload, so a value
    /// asking for one is answered with [`CodecError::InvalidField`] and
    /// nothing is written.
    ///
    /// The per-draft `encode` methods are unchanged and still infallible; they
    /// take the framing the value names as the authority and silently discard
    /// whatever does not fit it. Reach for one of those only when that is what
    /// you want.
    #[derive(Debug, Clone)]
    pub enum AnyDatagramHeader {
        #[cfg(feature = "draft07")]
        Draft07 => crate::draft07::data_stream::Datagram,
        #[cfg(feature = "draft08")]
        Draft08 => crate::draft08::data_stream::Datagram,
        #[cfg(feature = "draft09")]
        Draft09 => crate::draft09::data_stream::Datagram,
        #[cfg(feature = "draft10")]
        Draft10 => crate::draft10::data_stream::Datagram,
        #[cfg(feature = "draft11")]
        Draft11 => crate::draft11::data_stream::Datagram,
        #[cfg(feature = "draft12")]
        Draft12 => crate::draft12::data_stream::Datagram,
        #[cfg(feature = "draft13")]
        Draft13 => crate::draft13::data_stream::Datagram,
        #[cfg(feature = "draft14")]
        Draft14 => crate::draft14::data_stream::DatagramObject,
        #[cfg(feature = "draft15")]
        Draft15 => crate::draft15::data_stream::DatagramHeader,
        #[cfg(feature = "draft16")]
        Draft16 => crate::draft16::data_stream::DatagramHeader,
        #[cfg(feature = "draft17")]
        Draft17 => crate::draft17::data_stream::DatagramHeader,
        #[cfg(feature = "draft18")]
        Draft18 => crate::draft18::data_stream::DatagramHeader,
        #[cfg(feature = "draft19")]
        Draft19 => crate::draft19::data_stream::DatagramHeader,
    }
    decode(decode);
    encode(encode_checked -> Result<(), CodecError>);
}

/// One datagram's identity, resolved, without its payload.
///
/// The five fields a caller keys on, taken off whichever of the thirteen
/// per-draft datagram shapes this value holds. Produced by
/// [`AnyDatagramHeader::meta`], and the reason it exists is that the shapes
/// disagree about far more than their field order: drafts 07 through 13 split
/// a payload datagram and a status datagram into two structs, draft-14 merges
/// them behind an optional status, and drafts 15 through 19 hang both the
/// status and the priority off bits in a type byte.
///
/// Every field is a primitive, so keying on a datagram never means naming a
/// per-draft codec type — the same contract
/// [`AnySubgroupObjectMeta`] holds for a subgroup object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnyDatagramMeta {
    /// Track alias identifying the subscription this datagram answers.
    pub track_alias: u64,
    /// Group ID.
    pub group_id: u64,
    /// Object ID.
    ///
    /// Always a value, on every draft, including the six whose type byte can
    /// leave the field off the wire. Drafts 14 through 19 give the omission a
    /// meaning rather than making the field absent — draft-16 Section 10.3.1:
    /// "The ZERO_OBJECT_ID bit (0x04) indicates when the Object ID field is
    /// present. When set to 1, the Object ID field is omitted and the Object
    /// ID is 0." So the zero behind an omitted field is the Object's ID and
    /// not a placeholder standing in for one, which is the opposite of what a
    /// fetch object's absent Subgroup ID means and is why this field is not an
    /// `Option`.
    pub object_id: u64,
    /// Publisher priority, or `None` where the datagram states none.
    ///
    /// Absent only on drafts 15 through 19, whose type byte carries a
    /// default-priority bit; an Object that leaves it clear takes the priority
    /// the control message that established the subscription specified, which
    /// is not on this datagram and not knowable from it. Drafts 07 through 14
    /// always carry the field.
    pub publisher_priority: Option<u8>,
    /// The Object Status this datagram states, or `None` when it carries a
    /// payload instead.
    ///
    /// The framing decides which, and each cohort frames it differently: a
    /// declared payload length of zero on drafts 07 and 08, a separate status
    /// datagram on 08 through 13, an optional field on 14, and a status bit in
    /// the type byte from 15 on. Draft-08 appears in that list twice because it
    /// states a status both ways — it kept draft-07's optional status field
    /// under a zero payload length and added OBJECT_DATAGRAM_STATUS beside it,
    /// and draft-09 is where the first of the two goes away. The code is always
    /// one the draft assigns, because every draft's decoder refuses the values
    /// it does not.
    pub status: Option<u64>,
}

impl AnyDatagramHeader {
    /// This datagram's identity, without its payload.
    ///
    /// One call in place of thirteen match arms. A caller that wants a track
    /// alias, a Location or a priority off a datagram has otherwise to
    /// destructure the concrete per-draft variant — and on drafts 07 through 13
    /// to destructure again, because those carry a payload datagram and a
    /// status datagram as two different structs behind one enum.
    ///
    /// See [`AnyDatagramMeta::object_id`] for the one field whose absence from
    /// the wire is not an absence of the value.
    #[allow(unreachable_patterns)]
    pub fn meta(&self) -> AnyDatagramMeta {
        /// Drafts 09 through 13, which are the same two-struct shape five
        /// times: the payload form carries no status field at all, so the
        /// enum arm is the whole of the answer.
        ///
        /// Gated on the five it serves. A build carrying none of them has no
        /// caller for it, and an ungated definition would be a `-D warnings`
        /// error on every such per-draft row rather than on the all-features
        /// build a reviewer runs.
        #[cfg(any(
            feature = "draft09",
            feature = "draft10",
            feature = "draft11",
            feature = "draft12",
            feature = "draft13"
        ))]
        macro_rules! split_datagram {
            ($module:ident, $value:expr) => {
                match $value {
                    crate::$module::data_stream::Datagram::Payload(h) => AnyDatagramMeta {
                        track_alias: h.track_alias.into_inner(),
                        group_id: h.group_id.into_inner(),
                        object_id: h.object_id.into_inner(),
                        publisher_priority: Some(h.publisher_priority),
                        status: None,
                    },
                    crate::$module::data_stream::Datagram::Status(h) => AnyDatagramMeta {
                        track_alias: h.track_alias.into_inner(),
                        group_id: h.group_id.into_inner(),
                        object_id: h.object_id.into_inner(),
                        publisher_priority: Some(h.publisher_priority),
                        status: Some(h.object_status.as_u64()),
                    },
                }
            };
        }

        match self {
            // Drafts 07 and 08 are the two that hang a status off a declared
            // payload length of zero, so on both the payload form can state one
            // and the enum arm is not the whole of the answer. Draft-07's
            // OBJECT_DATAGRAM is `… Object Payload Length (i), [Object Status
            // (i)], Object Payload (..)` and it is the only datagram that draft
            // has; draft-08 keeps that layout and adds OBJECT_DATAGRAM_STATUS
            // beside it, so it says the same thing two ways. Draft-09 dropped
            // both the length and the status from the payload form, which is
            // why every draft from there on can read the arm alone.
            #[cfg(feature = "draft07")]
            AnyDatagramHeader::Draft07(d) => {
                let states_status = d.is_status();
                match d {
                    crate::draft07::data_stream::Datagram::Payload(h) => AnyDatagramMeta {
                        track_alias: h.track_alias.into_inner(),
                        group_id: h.group_id.into_inner(),
                        object_id: h.object_id.into_inner(),
                        publisher_priority: Some(h.publisher_priority),
                        status: states_status.then(|| h.object_status.as_u64()),
                    },
                }
            }
            #[cfg(feature = "draft08")]
            AnyDatagramHeader::Draft08(d) => {
                let states_status = d.is_status();
                match d {
                    crate::draft08::data_stream::Datagram::Payload(h) => AnyDatagramMeta {
                        track_alias: h.track_alias.into_inner(),
                        group_id: h.group_id.into_inner(),
                        object_id: h.object_id.into_inner(),
                        publisher_priority: Some(h.publisher_priority),
                        status: states_status.then(|| h.object_status.as_u64()),
                    },
                    crate::draft08::data_stream::Datagram::Status(h) => AnyDatagramMeta {
                        track_alias: h.track_alias.into_inner(),
                        group_id: h.group_id.into_inner(),
                        object_id: h.object_id.into_inner(),
                        publisher_priority: Some(h.publisher_priority),
                        status: Some(h.object_status.as_u64()),
                    },
                }
            }
            #[cfg(feature = "draft09")]
            AnyDatagramHeader::Draft09(d) => split_datagram!(draft09, d),
            #[cfg(feature = "draft10")]
            AnyDatagramHeader::Draft10(d) => split_datagram!(draft10, d),
            #[cfg(feature = "draft11")]
            AnyDatagramHeader::Draft11(d) => split_datagram!(draft11, d),
            #[cfg(feature = "draft12")]
            AnyDatagramHeader::Draft12(d) => split_datagram!(draft12, d),
            #[cfg(feature = "draft13")]
            AnyDatagramHeader::Draft13(d) => split_datagram!(draft13, d),
            #[cfg(feature = "draft14")]
            AnyDatagramHeader::Draft14(d) => AnyDatagramMeta {
                track_alias: d.track_alias.into_inner(),
                group_id: d.group_id.into_inner(),
                object_id: d.object_id.into_inner(),
                publisher_priority: Some(d.publisher_priority),
                status: d.status.map(|s| s.as_u64()),
            },
            // Drafts 15 and 16 write the status field whenever the type byte's
            // status bit is set, and an unset value under a set bit encodes as
            // Normal — so the bit is the authority on presence and the field is
            // the authority on nothing else.
            #[cfg(feature = "draft15")]
            AnyDatagramHeader::Draft15(d) => AnyDatagramMeta {
                track_alias: d.track_alias.into_inner(),
                group_id: d.group_id.into_inner(),
                object_id: d.object_id.into_inner(),
                publisher_priority: d.publisher_priority,
                status: d.is_status().then(|| {
                    d.object_status.unwrap_or(crate::draft15::types::ObjectStatus::Normal).as_u64()
                }),
            },
            #[cfg(feature = "draft16")]
            AnyDatagramHeader::Draft16(d) => AnyDatagramMeta {
                track_alias: d.track_alias.into_inner(),
                group_id: d.group_id.into_inner(),
                object_id: d.object_id.into_inner(),
                publisher_priority: d.publisher_priority,
                status: d.is_status().then(|| {
                    d.object_status.unwrap_or(crate::draft16::types::ObjectStatus::Normal).as_u64()
                }),
            },
            // Drafts 17 through 19 resolve the same pair themselves.
            #[cfg(feature = "draft17")]
            AnyDatagramHeader::Draft17(d) => AnyDatagramMeta {
                track_alias: d.track_alias.into_inner(),
                group_id: d.group_id.into_inner(),
                object_id: d.object_id.into_inner(),
                publisher_priority: d.publisher_priority,
                status: d.has_status().then(|| d.status().as_u64()),
            },
            #[cfg(feature = "draft18")]
            AnyDatagramHeader::Draft18(d) => AnyDatagramMeta {
                track_alias: d.track_alias.into_inner(),
                group_id: d.group_id.into_inner(),
                object_id: d.object_id.into_inner(),
                publisher_priority: d.publisher_priority,
                status: d.has_status().then(|| d.status().as_u64()),
            },
            #[cfg(feature = "draft19")]
            AnyDatagramHeader::Draft19(d) => AnyDatagramMeta {
                track_alias: d.track_alias.into_inner(),
                group_id: d.group_id.into_inner(),
                object_id: d.object_id.into_inner(),
                publisher_priority: d.publisher_priority,
                status: d.has_status().then(|| d.status().as_u64()),
            },
            _ => unreachable!("AnyDatagramHeader has no enabled variants"),
        }
    }

    /// Whether this datagram may carry a non-empty payload.
    ///
    /// Drafts 07 through 18 state one blanket rule — "Any object with a status
    /// code other than zero MUST have an empty payload" — and draft-19 replaces
    /// it with a Payload column in the Object Status registry of its Section
    /// 15.9, which grants a payload to the same one status the blanket rule
    /// did. The answer is therefore the same shape on all thirteen, and it is
    /// the framing that gives it: every draft either splits payload and status
    /// datagrams into separate types (08 through 14, and the type byte on 15
    /// and 16) or hangs the status off a declared length of zero (07), so a
    /// datagram that states a status is one that has no payload to carry.
    ///
    /// Note this asks what the framing *permits*, not what the value holds. A
    /// datagram permitted a payload may still carry none; a zero-length Normal
    /// object is legal everywhere.
    ///
    /// Before this, a caller had to match the concrete per-draft variant to ask
    /// at all, which is why the client carries thirteen arms to do it.
    #[allow(unreachable_patterns)]
    pub fn permits_payload(&self) -> bool {
        match self {
            #[cfg(feature = "draft07")]
            AnyDatagramHeader::Draft07(d) => !d.is_status(),
            #[cfg(feature = "draft08")]
            AnyDatagramHeader::Draft08(d) => !d.is_status(),
            #[cfg(feature = "draft09")]
            AnyDatagramHeader::Draft09(d) => !d.is_status(),
            #[cfg(feature = "draft10")]
            AnyDatagramHeader::Draft10(d) => !d.is_status(),
            #[cfg(feature = "draft11")]
            AnyDatagramHeader::Draft11(d) => !d.is_status(),
            #[cfg(feature = "draft12")]
            AnyDatagramHeader::Draft12(d) => !d.is_status(),
            #[cfg(feature = "draft13")]
            AnyDatagramHeader::Draft13(d) => !d.is_status(),
            #[cfg(feature = "draft14")]
            AnyDatagramHeader::Draft14(d) => !d.datagram_type.is_status(),
            #[cfg(feature = "draft15")]
            AnyDatagramHeader::Draft15(d) => !d.is_status(),
            #[cfg(feature = "draft16")]
            AnyDatagramHeader::Draft16(d) => !d.is_status(),
            // Drafts 17-19 answer the per-status question directly, which on 19
            // is the registry column rather than the blanket rule.
            #[cfg(feature = "draft17")]
            AnyDatagramHeader::Draft17(d) => d.permits_payload(),
            #[cfg(feature = "draft18")]
            AnyDatagramHeader::Draft18(d) => d.permits_payload(),
            #[cfg(feature = "draft19")]
            AnyDatagramHeader::Draft19(d) => d.permits_payload(),
            _ => unreachable!("AnyDatagramHeader has no enabled variants"),
        }
    }

    /// Whether this datagram's status is allowed to carry the extension headers
    /// it has, or `None` where the draft states no such rule.
    ///
    /// The rule enters the specification twice, in two different widths, and a
    /// draft-neutral caller must not apply either one outside its range:
    ///
    /// - **Drafts 07 through 10 state nothing.** Draft-07's datagram has no
    ///   extension block at all, and drafts 08, 09 and 10 have one with no rule
    ///   attached. These answer `None` rather than `true`, because "permitted"
    ///   would imply a rule was consulted.
    /// - **Drafts 11 through 14 state the narrow form**, in the section naming
    ///   the Object Extension Header: "Any Object may have extension headers
    ///   except those with Object Status 'Object Does Not Exist'." One status,
    ///   and End of Group and End of Track may carry extensions freely.
    /// - **Drafts 15 through 19 state the general form**: "Any Object with
    ///   status Normal can have extension headers. If an endpoint receives
    ///   extension headers on Objects with status that is not Normal, it MUST
    ///   close the session with a PROTOCOL_VIOLATION." Draft-16 also dropped
    ///   the Object Does Not Exist status, so the narrow form's subject no
    ///   longer exists there.
    ///
    /// Drafts 17 and later call the block Properties rather than Extensions;
    /// the name here follows [`AnySubgroupObject::extension_headers`], which
    /// spans the same rename.
    ///
    /// This reports rather than refuses, on all thirteen. A frame carrying
    /// extensions beside a status is well formed — every length is honest and
    /// every field parses — so a decoder hands it back intact and a tool that
    /// reproduces a capture can re-emit it. Refusing on decode would make a
    /// captured violation unreadable, which loses the one artifact anybody
    /// debugging it needs.
    #[allow(unreachable_patterns)]
    pub fn extensions_permitted(&self) -> Option<bool> {
        match self {
            // No rule stated: see above.
            #[cfg(feature = "draft07")]
            AnyDatagramHeader::Draft07(_) => None,
            #[cfg(feature = "draft08")]
            AnyDatagramHeader::Draft08(_) => None,
            #[cfg(feature = "draft09")]
            AnyDatagramHeader::Draft09(_) => None,
            #[cfg(feature = "draft10")]
            AnyDatagramHeader::Draft10(_) => None,
            // The narrow form. A payload datagram's status is Normal, so only
            // the status form can state the violation.
            #[cfg(feature = "draft11")]
            AnyDatagramHeader::Draft11(d) => Some(match d {
                crate::draft11::data_stream::Datagram::Payload(_) => true,
                crate::draft11::data_stream::Datagram::Status(s) => {
                    s.extensions.is_empty()
                        || s.object_status
                            != crate::draft11::types::ObjectStatus::ObjectDoesNotExist
                }
            }),
            #[cfg(feature = "draft12")]
            AnyDatagramHeader::Draft12(d) => Some(match d {
                crate::draft12::data_stream::Datagram::Payload(_) => true,
                crate::draft12::data_stream::Datagram::Status(s) => {
                    s.extensions.is_empty()
                        || s.object_status
                            != crate::draft12::types::ObjectStatus::ObjectDoesNotExist
                }
            }),
            #[cfg(feature = "draft13")]
            AnyDatagramHeader::Draft13(d) => Some(match d {
                crate::draft13::data_stream::Datagram::Payload(_) => true,
                crate::draft13::data_stream::Datagram::Status(s) => {
                    s.extensions.is_empty()
                        || s.object_status
                            != crate::draft13::types::ObjectStatus::ObjectDoesNotExist
                }
            }),
            // Draft-14 folds both forms into one value, so an absent status
            // means Normal rather than *no status field here*.
            #[cfg(feature = "draft14")]
            AnyDatagramHeader::Draft14(d) => Some(
                d.extension_headers.is_empty()
                    || d.status != Some(crate::draft14::types::ObjectStatus::ObjectDoesNotExist),
            ),
            // The general form, already answered per draft.
            #[cfg(feature = "draft15")]
            AnyDatagramHeader::Draft15(d) => Some(d.extensions_permitted()),
            #[cfg(feature = "draft16")]
            AnyDatagramHeader::Draft16(d) => Some(d.extensions_permitted()),
            #[cfg(feature = "draft17")]
            AnyDatagramHeader::Draft17(d) => Some(d.properties_permitted()),
            #[cfg(feature = "draft18")]
            AnyDatagramHeader::Draft18(d) => Some(d.properties_permitted()),
            #[cfg(feature = "draft19")]
            AnyDatagramHeader::Draft19(d) => Some(d.properties_permitted()),
            _ => unreachable!("AnyDatagramHeader has no enabled variants"),
        }
    }
}

dispatch_enum! {
    /// A fetch header from any enabled draft.
    ///
    /// Note: Header structure varies significantly across drafts.
    /// Draft-07 has a minimal fetch header, Draft-14 has a full header.
    #[derive(Debug, Clone)]
    pub enum AnyFetchHeader {
        #[cfg(feature = "draft07")]
        Draft07 => crate::draft07::data_stream::FetchHeader,
        #[cfg(feature = "draft08")]
        Draft08 => crate::draft08::data_stream::FetchHeader,
        #[cfg(feature = "draft09")]
        Draft09 => crate::draft09::data_stream::FetchHeader,
        #[cfg(feature = "draft10")]
        Draft10 => crate::draft10::data_stream::FetchHeader,
        #[cfg(feature = "draft11")]
        Draft11 => crate::draft11::data_stream::FetchHeader,
        #[cfg(feature = "draft12")]
        Draft12 => crate::draft12::data_stream::FetchHeader,
        #[cfg(feature = "draft13")]
        Draft13 => crate::draft13::data_stream::FetchHeader,
        #[cfg(feature = "draft14")]
        Draft14 => crate::draft14::data_stream::FetchHeader,
        #[cfg(feature = "draft15")]
        Draft15 => crate::draft15::data_stream::FetchHeader,
        #[cfg(feature = "draft16")]
        Draft16 => crate::draft16::data_stream::FetchHeader,
        #[cfg(feature = "draft17")]
        Draft17 => crate::draft17::data_stream::FetchHeader,
        #[cfg(feature = "draft18")]
        Draft18 => crate::draft18::data_stream::FetchHeader,
        #[cfg(feature = "draft19")]
        Draft19 => crate::draft19::data_stream::FetchHeader,
    }
    decode(decode);
    encode(encode -> ());
}

impl AnyFetchHeader {
    /// The id of the request this fetch stream answers.
    ///
    /// Every draft puts it in the header and nothing else: drafts 07-10 call
    /// it the Subscribe ID and drafts 11-19 the Request ID, and it names the
    /// request the publisher is responding to either way. Draft-19 Section
    /// 11.4.4: "When a stream begins with FETCH_HEADER, all objects on the
    /// stream belong to the track requested in the Fetch message identified by
    /// Request ID."
    ///
    /// It is what ties a fetch data stream back to the control exchange that
    /// opened it, which is the only route by which anything the stream does
    /// not state — on drafts 18 and 19, the Group Order its Group ID Deltas
    /// resolve against — can reach a reader.
    #[allow(unreachable_patterns)]
    pub fn request_id(&self) -> u64 {
        match self {
            #[cfg(feature = "draft07")]
            AnyFetchHeader::Draft07(h) => h.subscribe_id.into_inner(),
            #[cfg(feature = "draft08")]
            AnyFetchHeader::Draft08(h) => h.subscribe_id.into_inner(),
            #[cfg(feature = "draft09")]
            AnyFetchHeader::Draft09(h) => h.subscribe_id.into_inner(),
            #[cfg(feature = "draft10")]
            AnyFetchHeader::Draft10(h) => h.subscribe_id.into_inner(),
            #[cfg(feature = "draft11")]
            AnyFetchHeader::Draft11(h) => h.request_id.into_inner(),
            #[cfg(feature = "draft12")]
            AnyFetchHeader::Draft12(h) => h.request_id.into_inner(),
            #[cfg(feature = "draft13")]
            AnyFetchHeader::Draft13(h) => h.request_id.into_inner(),
            #[cfg(feature = "draft14")]
            AnyFetchHeader::Draft14(h) => h.request_id.into_inner(),
            #[cfg(feature = "draft15")]
            AnyFetchHeader::Draft15(h) => h.request_id.into_inner(),
            #[cfg(feature = "draft16")]
            AnyFetchHeader::Draft16(h) => h.request_id.into_inner(),
            #[cfg(feature = "draft17")]
            AnyFetchHeader::Draft17(h) => h.request_id.into_inner(),
            #[cfg(feature = "draft18")]
            AnyFetchHeader::Draft18(h) => h.request_id.into_inner(),
            #[cfg(feature = "draft19")]
            AnyFetchHeader::Draft19(h) => h.request_id.into_inner(),
            _ => unreachable!("AnyFetchHeader has no enabled variants"),
        }
    }

    /// As [`AnySubgroupHeader::encode_stream`], for fetch streams.
    ///
    /// Fetch was the carrier this pair was missing: `decode_stream` has
    /// existed here all along with nothing on the other side of it, so a
    /// fetch stream the codec wrote could not be read back by the codec.
    #[allow(unreachable_code, unused_variables)]
    pub fn encode_stream(&self, buf: &mut impl BufMut) {
        match self {
            #[cfg(feature = "draft07")]
            AnyFetchHeader::Draft07(h) => h.encode_stream(buf),
            #[cfg(feature = "draft08")]
            AnyFetchHeader::Draft08(h) => h.encode_stream(buf),
            #[cfg(feature = "draft09")]
            AnyFetchHeader::Draft09(h) => h.encode_stream(buf),
            #[cfg(feature = "draft10")]
            AnyFetchHeader::Draft10(h) => h.encode_stream(buf),
            #[cfg(feature = "draft11")]
            AnyFetchHeader::Draft11(h) => h.encode_stream(buf),
            #[cfg(feature = "draft12")]
            AnyFetchHeader::Draft12(h) => h.encode_stream(buf),
            #[cfg(feature = "draft13")]
            AnyFetchHeader::Draft13(h) => h.encode_stream(buf),
            // Drafts 14-19 fold the stream type into the header, so their
            // `encode` already writes it and `decode_stream` already reads
            // it back.
            #[cfg(feature = "draft14")]
            AnyFetchHeader::Draft14(h) => h.encode(buf),
            #[cfg(feature = "draft15")]
            AnyFetchHeader::Draft15(h) => h.encode(buf),
            #[cfg(feature = "draft16")]
            AnyFetchHeader::Draft16(h) => h.encode(buf),
            #[cfg(feature = "draft17")]
            AnyFetchHeader::Draft17(h) => h.encode(buf),
            #[cfg(feature = "draft18")]
            AnyFetchHeader::Draft18(h) => h.encode(buf),
            #[cfg(feature = "draft19")]
            AnyFetchHeader::Draft19(h) => h.encode(buf),
            #[allow(unreachable_patterns)]
            _ => unreachable!("AnyFetchHeader has no enabled variants"),
        }
    }

    /// As [`AnySubgroupHeader::decode_stream`], for fetch streams.
    #[allow(unused_variables)]
    pub fn decode_stream(version: DraftVersion, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match version {
            #[cfg(feature = "draft07")]
            DraftVersion::Draft07 => crate::draft07::data_stream::FetchHeader::decode_stream(buf)
                .map(AnyFetchHeader::Draft07),
            #[cfg(feature = "draft08")]
            DraftVersion::Draft08 => crate::draft08::data_stream::FetchHeader::decode_stream(buf)
                .map(AnyFetchHeader::Draft08),
            #[cfg(feature = "draft09")]
            DraftVersion::Draft09 => crate::draft09::data_stream::FetchHeader::decode_stream(buf)
                .map(AnyFetchHeader::Draft09),
            #[cfg(feature = "draft10")]
            DraftVersion::Draft10 => crate::draft10::data_stream::FetchHeader::decode_stream(buf)
                .map(AnyFetchHeader::Draft10),
            #[cfg(feature = "draft11")]
            DraftVersion::Draft11 => crate::draft11::data_stream::FetchHeader::decode_stream(buf)
                .map(AnyFetchHeader::Draft11),
            #[cfg(feature = "draft12")]
            DraftVersion::Draft12 => crate::draft12::data_stream::FetchHeader::decode_stream(buf)
                .map(AnyFetchHeader::Draft12),
            #[cfg(feature = "draft13")]
            DraftVersion::Draft13 => crate::draft13::data_stream::FetchHeader::decode_stream(buf)
                .map(AnyFetchHeader::Draft13),
            #[cfg(feature = "draft14")]
            DraftVersion::Draft14 => {
                crate::draft14::data_stream::FetchHeader::decode(buf).map(AnyFetchHeader::Draft14)
            }
            #[cfg(feature = "draft15")]
            DraftVersion::Draft15 => {
                crate::draft15::data_stream::FetchHeader::decode(buf).map(AnyFetchHeader::Draft15)
            }
            #[cfg(feature = "draft16")]
            DraftVersion::Draft16 => {
                crate::draft16::data_stream::FetchHeader::decode(buf).map(AnyFetchHeader::Draft16)
            }
            #[cfg(feature = "draft17")]
            DraftVersion::Draft17 => {
                crate::draft17::data_stream::FetchHeader::decode(buf).map(AnyFetchHeader::Draft17)
            }
            #[cfg(feature = "draft18")]
            DraftVersion::Draft18 => {
                crate::draft18::data_stream::FetchHeader::decode(buf).map(AnyFetchHeader::Draft18)
            }
            #[cfg(feature = "draft19")]
            DraftVersion::Draft19 => {
                crate::draft19::data_stream::FetchHeader::decode(buf).map(AnyFetchHeader::Draft19)
            }
            #[allow(unreachable_patterns)]
            _ => Err(CodecError::UnsupportedDraft(format!(
                "draft {version:?} not enabled via feature flag"
            ))),
        }
    }
}

// The one test below drives drafts 07, 12 and 18, each standing for one of the
// three framing shapes. Under a feature set naming none of them every arm
// compiles away, leaving the import with no user, so the module is gated on the
// same three rather than on `test` alone.
#[cfg(all(test, any(feature = "draft07", feature = "draft12", feature = "draft18")))]
mod tests {
    use super::*;

    /// The draft-neutral entry point carries each draft's refusal out to the
    /// caller instead of resolving it the way the per-draft `encode` does.
    ///
    /// This is what changed for a caller holding an [`AnyDatagramHeader`]:
    /// [`AnyDatagramHeader::encode`] used to return `()` on all thirteen
    /// drafts, so a header whose Object Status its framing could not carry went
    /// out with the status quietly removed. It now dispatches to each draft's
    /// `encode_checked` and answers [`CodecError::InvalidField`] without
    /// writing a byte.
    ///
    /// Three drafts are driven here, one per shape the thirteen fall into.
    /// Draft-07 hangs the status field off a zero Object Payload Length;
    /// draft-18 hangs it off the STATUS bit in the type byte; draft-12 has no
    /// status field on this message at all, its statuses travelling on a
    /// separate OBJECT_DATAGRAM_STATUS, and so must keep accepting every header
    /// a publisher may send. A build with only some drafts enabled compiles
    /// only the arms it has.
    ///
    /// # What this catches, observed by making the change and running it
    ///
    /// Dropping the check from draft-07's `DatagramHeader::encode_checked`, so
    /// the dispatch layer has nothing to carry out:
    ///
    /// ```text
    /// draft-07 must refuse a status its framing cannot carry; got Ok(())
    /// ```
    #[test]
    fn any_datagram_header_encode_refuses_what_the_framing_cannot_carry() {
        #[cfg(feature = "draft07")]
        {
            let header =
                AnyDatagramHeader::Draft07(crate::draft07::data_stream::Datagram::Payload(
                    crate::draft07::data_stream::DatagramHeader {
                        track_alias: crate::varint::VarInt::from_usize(1),
                        group_id: crate::varint::VarInt::from_usize(0),
                        object_id: crate::varint::VarInt::from_usize(0),
                        publisher_priority: 128,
                        object_status: crate::draft07::types::ObjectStatus::EndOfGroup,
                        payload_length: crate::varint::VarInt::from_usize(4),
                    },
                ));
            let mut buf = Vec::new();
            let result = header.encode(&mut buf);
            assert!(
                matches!(result, Err(CodecError::InvalidField)),
                "draft-07 must refuse a status its framing cannot carry; got {result:?}"
            );
            assert!(buf.is_empty(), "draft-07 wrote {buf:?} for a header it refused");
        }

        #[cfg(feature = "draft18")]
        {
            let header = AnyDatagramHeader::Draft18(crate::draft18::data_stream::DatagramHeader {
                // Type 0x00: every flag clear, so the STATUS bit is clear and
                // a payload follows the header.
                datagram_type: 0x00,
                track_alias: crate::varint::VarInt::from_usize(1),
                group_id: crate::varint::VarInt::from_usize(0),
                object_id: crate::varint::VarInt::from_usize(0),
                publisher_priority: Some(128),
                properties: Vec::new(),
                object_status: Some(crate::draft18::types::ObjectStatus::EndOfGroup),
            });
            let mut buf = Vec::new();
            let result = header.encode(&mut buf);
            assert!(
                matches!(result, Err(CodecError::InvalidField)),
                "draft-18 must refuse a status its framing cannot carry; got {result:?}"
            );
            assert!(buf.is_empty(), "draft-18 wrote {buf:?} for a header it refused");
        }

        #[cfg(feature = "draft12")]
        {
            let header =
                AnyDatagramHeader::Draft12(crate::draft12::data_stream::Datagram::Payload(
                    crate::draft12::data_stream::DatagramHeader {
                        track_alias: crate::varint::VarInt::from_usize(1),
                        group_id: crate::varint::VarInt::from_usize(0),
                        object_id: crate::varint::VarInt::from_usize(7),
                        publisher_priority: 128,
                        extension_headers_length: crate::varint::VarInt::from_usize(0),
                        extensions: Vec::new(),
                        end_of_group: false,
                    },
                ));
            let mut buf = Vec::new();
            header
                .encode(&mut buf)
                .expect("draft-12's payload datagram carries no status to refuse");
            let mut cursor = &buf[..];
            let decoded = AnyDatagramHeader::decode(DraftVersion::Draft12, &mut cursor)
                .expect("the bytes the dispatch layer wrote must parse back");
            assert_eq!(decoded.draft(), DraftVersion::Draft12);
            assert!(!cursor.has_remaining(), "draft-12 left {cursor:?} unread");
        }
    }

    /// The draft-neutral predicates answer the two questions that previously
    /// required matching the concrete per-draft variant.
    ///
    /// The same three drafts stand for the three eras of the extensions rule.
    /// Draft-07 has no extension block and no rule, and must answer `None`
    /// rather than `true` — reporting "permitted" would claim a rule was
    /// consulted. Draft-12 states the narrow form, so an extension block is a
    /// violation beside Object Does Not Exist and legal beside End of Group.
    /// Draft-18 states the general form, where both are violations.
    ///
    /// # What this catches, observed by making the change and running it
    ///
    /// Widening draft-12's arm to the general form, by comparing its status
    /// against `Normal` instead of against `ObjectDoesNotExist`:
    ///
    /// ```text
    /// draft-12 states the narrow form, which leaves End of Group free to
    /// carry extensions: expected Some(true), got Some(false)
    /// ```
    #[test]
    fn any_datagram_header_reports_payload_and_extension_permission() {
        #[cfg(feature = "draft07")]
        {
            let status =
                AnyDatagramHeader::Draft07(crate::draft07::data_stream::Datagram::Payload(
                    crate::draft07::data_stream::DatagramHeader {
                        track_alias: crate::varint::VarInt::from_usize(1),
                        group_id: crate::varint::VarInt::from_usize(0),
                        object_id: crate::varint::VarInt::from_usize(0),
                        publisher_priority: 128,
                        object_status: crate::draft07::types::ObjectStatus::EndOfGroup,
                        // Draft-07 has one datagram layout and hangs the status
                        // off a zero length, so this is what makes it a status.
                        payload_length: crate::varint::VarInt::from_usize(0),
                    },
                ));
            assert!(
                !status.permits_payload(),
                "draft-07 declares no payload bytes, so it may not carry any",
            );
            assert_eq!(
                status.extensions_permitted(),
                None,
                "draft-07 has no extension block and states no rule about one",
            );
        }

        #[cfg(feature = "draft12")]
        {
            let with_extensions = |object_status| {
                AnyDatagramHeader::Draft12(crate::draft12::data_stream::Datagram::Status(
                    crate::draft12::data_stream::DatagramStatusHeader {
                        track_alias: crate::varint::VarInt::from_usize(1),
                        group_id: crate::varint::VarInt::from_usize(0),
                        object_id: crate::varint::VarInt::from_usize(0),
                        publisher_priority: 128,
                        extension_headers_length: crate::varint::VarInt::from_usize(2),
                        extensions: vec![0x3c, 0x01],
                        object_status,
                    },
                ))
            };

            let absent = with_extensions(crate::draft12::types::ObjectStatus::ObjectDoesNotExist);
            assert!(!absent.permits_payload(), "a status datagram carries no payload");
            assert_eq!(
                absent.extensions_permitted(),
                Some(false),
                "Object Does Not Exist is the one status draft-12 bars extensions from",
            );

            let end_of_group = with_extensions(crate::draft12::types::ObjectStatus::EndOfGroup);
            assert_eq!(
                end_of_group.extensions_permitted(),
                Some(true),
                "draft-12 states the narrow form, which leaves End of Group free to \
                 carry extensions: expected Some(true), got {:?}",
                end_of_group.extensions_permitted(),
            );
        }

        #[cfg(feature = "draft18")]
        {
            // Type 0x21: the STATUS bit and the properties bit both set.
            let header = |object_status| {
                AnyDatagramHeader::Draft18(crate::draft18::data_stream::DatagramHeader {
                    datagram_type: 0x21,
                    track_alias: crate::varint::VarInt::from_usize(1),
                    group_id: crate::varint::VarInt::from_usize(0),
                    object_id: crate::varint::VarInt::from_usize(0),
                    publisher_priority: Some(128),
                    properties: vec![0x3c, 0x01],
                    object_status: Some(object_status),
                })
            };

            let end_of_group = header(crate::draft18::types::ObjectStatus::EndOfGroup);
            assert!(!end_of_group.permits_payload(), "a status datagram carries no payload");
            assert_eq!(
                end_of_group.extensions_permitted(),
                Some(false),
                "draft-18 states the general form, which bars properties beside any \
                 status that is not Normal",
            );
        }
    }
}

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
            #[allow(unreachable_patterns)]
            _ => false,
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
    }
    decode(decode);
    encode(encode -> ());
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
        // NOTE: drafts 14-17 have no standalone ObjectHeader. Subgroup
        // objects on those drafts use delta-encoded object IDs and
        // header-typed extension/properties presence flags, so
        // decoding requires stateful per-stream context. Callers must
        // use each draft's `SubgroupObjectReader` (or
        // `FetchObject::decode` for fetch streams) directly.
    }
    decode(decode);
    encode(encode -> ());
}

dispatch_enum! {
    /// A datagram header from any enabled draft.
    #[derive(Debug, Clone)]
    pub enum AnyDatagramHeader {
        #[cfg(feature = "draft07")]
        Draft07 => crate::draft07::data_stream::DatagramHeader,
        #[cfg(feature = "draft08")]
        Draft08 => crate::draft08::data_stream::DatagramHeader,
        #[cfg(feature = "draft09")]
        Draft09 => crate::draft09::data_stream::DatagramHeader,
        #[cfg(feature = "draft10")]
        Draft10 => crate::draft10::data_stream::DatagramHeader,
        #[cfg(feature = "draft11")]
        Draft11 => crate::draft11::data_stream::DatagramHeader,
        #[cfg(feature = "draft12")]
        Draft12 => crate::draft12::data_stream::DatagramHeader,
        #[cfg(feature = "draft13")]
        Draft13 => crate::draft13::data_stream::DatagramHeader,
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
    }
    decode(decode);
    encode(encode -> ());
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
    }
    decode(decode);
    encode(encode -> ());
}

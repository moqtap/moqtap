//! Unified types and version-aware decode/encode for runtime draft dispatch.
//!
//! This module is available when both `draft07` and `draft14` features are
//! enabled. It provides wrapper enums that hold either draft's types and
//! dispatch encoding/decoding based on [`crate::version::DraftVersion`].

use bytes::{Buf, BufMut};

use crate::error::CodecError;
use crate::version::DraftVersion;

// ── Control messages ────────────────────────────────────────

/// A control message from either draft.
#[derive(Debug, Clone)]
pub enum AnyControlMessage {
    /// Draft-07 control message.
    Draft07(crate::draft07::message::ControlMessage),
    /// Draft-14 control message.
    Draft14(crate::draft14::message::ControlMessage),
}

impl AnyControlMessage {
    /// Decode a control message using the specified draft version.
    pub fn decode(version: DraftVersion, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match version {
            DraftVersion::Draft07 => {
                crate::draft07::message::ControlMessage::decode(buf).map(AnyControlMessage::Draft07)
            }
            DraftVersion::Draft14 => {
                crate::draft14::message::ControlMessage::decode(buf).map(AnyControlMessage::Draft14)
            }
        }
    }

    /// Encode using the appropriate draft's framing.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        match self {
            AnyControlMessage::Draft07(m) => m.encode(buf),
            AnyControlMessage::Draft14(m) => m.encode(buf),
        }
    }

    /// Returns the draft version this message belongs to.
    pub fn draft(&self) -> DraftVersion {
        match self {
            AnyControlMessage::Draft07(_) => DraftVersion::Draft07,
            AnyControlMessage::Draft14(_) => DraftVersion::Draft14,
        }
    }
}

// ── Data stream headers ─────────────────────────────────────

/// A subgroup header from either draft.
#[derive(Debug, Clone)]
pub enum AnySubgroupHeader {
    /// Draft-07 subgroup header.
    Draft07(crate::draft07::data_stream::SubgroupHeader),
    /// Draft-14 subgroup header.
    Draft14(crate::draft14::data_stream::SubgroupHeader),
}

impl AnySubgroupHeader {
    /// Decode a subgroup header using the specified draft version.
    pub fn decode(version: DraftVersion, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match version {
            DraftVersion::Draft07 => crate::draft07::data_stream::SubgroupHeader::decode(buf)
                .map(AnySubgroupHeader::Draft07),
            DraftVersion::Draft14 => crate::draft14::data_stream::SubgroupHeader::decode(buf)
                .map(AnySubgroupHeader::Draft14),
        }
    }

    /// Encode using the appropriate draft's format.
    pub fn encode(&self, buf: &mut impl BufMut) {
        match self {
            AnySubgroupHeader::Draft07(h) => h.encode(buf),
            AnySubgroupHeader::Draft14(h) => h.encode(buf),
        }
    }
}

/// An object header from either draft.
#[derive(Debug, Clone)]
pub enum AnyObjectHeader {
    /// Draft-07 object header.
    Draft07(crate::draft07::data_stream::ObjectHeader),
    /// Draft-14 object header.
    Draft14(crate::draft14::data_stream::ObjectHeader),
}

impl AnyObjectHeader {
    /// Decode an object header using the specified draft version.
    pub fn decode(version: DraftVersion, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match version {
            DraftVersion::Draft07 => {
                crate::draft07::data_stream::ObjectHeader::decode(buf).map(AnyObjectHeader::Draft07)
            }
            DraftVersion::Draft14 => {
                crate::draft14::data_stream::ObjectHeader::decode(buf).map(AnyObjectHeader::Draft14)
            }
        }
    }

    /// Encode using the appropriate draft's format.
    pub fn encode(&self, buf: &mut impl BufMut) {
        match self {
            AnyObjectHeader::Draft07(h) => h.encode(buf),
            AnyObjectHeader::Draft14(h) => h.encode(buf),
        }
    }
}

/// A datagram header from either draft.
#[derive(Debug, Clone)]
pub enum AnyDatagramHeader {
    /// Draft-07 datagram header.
    Draft07(crate::draft07::data_stream::DatagramHeader),
    /// Draft-14 datagram header.
    Draft14(crate::draft14::data_stream::DatagramHeader),
}

impl AnyDatagramHeader {
    /// Decode a datagram header using the specified draft version.
    pub fn decode(version: DraftVersion, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match version {
            DraftVersion::Draft07 => crate::draft07::data_stream::DatagramHeader::decode(buf)
                .map(AnyDatagramHeader::Draft07),
            DraftVersion::Draft14 => crate::draft14::data_stream::DatagramHeader::decode(buf)
                .map(AnyDatagramHeader::Draft14),
        }
    }

    /// Encode using the appropriate draft's format.
    pub fn encode(&self, buf: &mut impl BufMut) {
        match self {
            AnyDatagramHeader::Draft07(h) => h.encode(buf),
            AnyDatagramHeader::Draft14(h) => h.encode(buf),
        }
    }
}

/// A fetch header from either draft.
///
/// Note: Draft-07 has a minimal fetch header (just subscribe_id),
/// while Draft-14 has a full header (track_alias, group, subgroup,
/// publisher_priority).
#[derive(Debug, Clone)]
pub enum AnyFetchHeader {
    /// Draft-07 fetch header.
    Draft07(crate::draft07::data_stream::FetchHeader),
    /// Draft-14 fetch header.
    Draft14(crate::draft14::data_stream::FetchHeader),
}

impl AnyFetchHeader {
    /// Decode a fetch header using the specified draft version.
    pub fn decode(version: DraftVersion, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match version {
            DraftVersion::Draft07 => {
                crate::draft07::data_stream::FetchHeader::decode(buf).map(AnyFetchHeader::Draft07)
            }
            DraftVersion::Draft14 => {
                crate::draft14::data_stream::FetchHeader::decode(buf).map(AnyFetchHeader::Draft14)
            }
        }
    }

    /// Encode using the appropriate draft's format.
    pub fn encode(&self, buf: &mut impl BufMut) {
        match self {
            AnyFetchHeader::Draft07(h) => h.encode(buf),
            AnyFetchHeader::Draft14(h) => h.encode(buf),
        }
    }
}

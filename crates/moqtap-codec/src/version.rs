//! MoQT draft version enum for runtime dispatch.

use crate::varint::VarInt;

/// MoQT draft version for runtime codec selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DraftVersion {
    /// draft-ietf-moq-transport-07.
    Draft07,
    /// draft-ietf-moq-transport-14.
    Draft14,
}

impl DraftVersion {
    /// The MoQT version number announced in CLIENT_SETUP.
    pub fn version_varint(&self) -> VarInt {
        match self {
            DraftVersion::Draft07 => VarInt::from_u64(0xff000000 + 7).unwrap(),
            DraftVersion::Draft14 => VarInt::from_u64(0xff000000 + 14).unwrap(),
        }
    }

    /// The ALPN protocol identifier for raw QUIC connections.
    pub fn quic_alpn(&self) -> &'static [u8] {
        match self {
            // Both drafts currently use the same ALPN
            DraftVersion::Draft07 => b"moq-00",
            DraftVersion::Draft14 => b"moq-00",
        }
    }
}

//! MoQT draft version enum for runtime dispatch.

use crate::varint::VarInt;

/// MoQT draft version for runtime codec selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DraftVersion {
    /// draft-ietf-moq-transport-07.
    Draft07,
    /// draft-ietf-moq-transport-08.
    Draft08,
    /// draft-ietf-moq-transport-09.
    Draft09,
    /// draft-ietf-moq-transport-10.
    Draft10,
    /// draft-ietf-moq-transport-11.
    Draft11,
    /// draft-ietf-moq-transport-12.
    Draft12,
    /// draft-ietf-moq-transport-13.
    Draft13,
    /// draft-ietf-moq-transport-14.
    Draft14,
    /// draft-ietf-moq-transport-15.
    Draft15,
    /// draft-ietf-moq-transport-16.
    Draft16,
    /// draft-ietf-moq-transport-17.
    Draft17,
    /// draft-ietf-moq-transport-18.
    Draft18,
}

impl DraftVersion {
    /// The MoQT version number announced in CLIENT_SETUP.
    ///
    /// Format: `0xff000000 + draft_number`. Draft-15+ use ALPN for version
    /// negotiation and may not include a version in CLIENT_SETUP at all.
    pub fn version_varint(&self) -> VarInt {
        let n = match self {
            DraftVersion::Draft07 => 7,
            DraftVersion::Draft08 => 8,
            DraftVersion::Draft09 => 9,
            DraftVersion::Draft10 => 10,
            DraftVersion::Draft11 => 11,
            DraftVersion::Draft12 => 12,
            DraftVersion::Draft13 => 13,
            DraftVersion::Draft14 => 14,
            DraftVersion::Draft15 => 15,
            DraftVersion::Draft16 => 16,
            DraftVersion::Draft17 => 17,
            DraftVersion::Draft18 => 18,
        };
        VarInt::from_usize(0xff000000 + n as usize)
    }

    /// The ALPN protocol identifier for raw QUIC connections.
    ///
    /// Drafts 07–14 all use `moq-00` and negotiate the draft version in
    /// CLIENT_SETUP / SERVER_SETUP. Draft-15+ encode the draft number in the
    /// ALPN itself (`moqt-<N>`), per §3.1.2 of each spec.
    pub fn quic_alpn(&self) -> &'static [u8] {
        match self {
            DraftVersion::Draft07
            | DraftVersion::Draft08
            | DraftVersion::Draft09
            | DraftVersion::Draft10
            | DraftVersion::Draft11
            | DraftVersion::Draft12
            | DraftVersion::Draft13
            | DraftVersion::Draft14 => b"moq-00",
            DraftVersion::Draft15 => b"moqt-15",
            DraftVersion::Draft16 => b"moqt-16",
            DraftVersion::Draft17 => b"moqt-17",
            DraftVersion::Draft18 => b"moqt-18",
        }
    }

    /// Resolve an ALPN identifier to a specific draft version.
    ///
    /// Returns `Some` for ALPNs that unambiguously identify a draft
    /// (`moqt-15`, `moqt-16`, `moqt-17`, `moqt-18`). Returns `None` for
    /// `moq-00` — which covers drafts 07–14 and requires inspecting
    /// CLIENT_SETUP's supported-versions list — and for any unrecognized
    /// ALPN.
    pub fn from_alpn(alpn: &[u8]) -> Option<DraftVersion> {
        match alpn {
            b"moqt-15" => Some(DraftVersion::Draft15),
            b"moqt-16" => Some(DraftVersion::Draft16),
            b"moqt-17" => Some(DraftVersion::Draft17),
            b"moqt-18" => Some(DraftVersion::Draft18),
            _ => None,
        }
    }

    /// Resolve a draft number (e.g. 7..=18) to a `DraftVersion`.
    ///
    /// Returns `None` for numbers outside the supported range.
    pub fn from_number(n: u8) -> Option<DraftVersion> {
        match n {
            7 => Some(DraftVersion::Draft07),
            8 => Some(DraftVersion::Draft08),
            9 => Some(DraftVersion::Draft09),
            10 => Some(DraftVersion::Draft10),
            11 => Some(DraftVersion::Draft11),
            12 => Some(DraftVersion::Draft12),
            13 => Some(DraftVersion::Draft13),
            14 => Some(DraftVersion::Draft14),
            15 => Some(DraftVersion::Draft15),
            16 => Some(DraftVersion::Draft16),
            17 => Some(DraftVersion::Draft17),
            18 => Some(DraftVersion::Draft18),
            _ => None,
        }
    }

    /// Whether this draft uses a 16-bit big-endian message length in control
    /// message framing (`true`) or a QUIC varint (`false`).
    ///
    /// Draft-11 changed the framing from `Length(i)` to `Length(16)`.
    pub fn uses_fixed_length_framing(&self) -> bool {
        self.number() >= 11
    }

    /// The draft number (e.g. 7, 14, 17).
    pub fn number(&self) -> u8 {
        match self {
            DraftVersion::Draft07 => 7,
            DraftVersion::Draft08 => 8,
            DraftVersion::Draft09 => 9,
            DraftVersion::Draft10 => 10,
            DraftVersion::Draft11 => 11,
            DraftVersion::Draft12 => 12,
            DraftVersion::Draft13 => 13,
            DraftVersion::Draft14 => 14,
            DraftVersion::Draft15 => 15,
            DraftVersion::Draft16 => 16,
            DraftVersion::Draft17 => 17,
            DraftVersion::Draft18 => 18,
        }
    }
}

impl std::fmt::Display for DraftVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "draft-{:02}", self.number())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_alpn_resolves_drafts_15_plus() {
        assert_eq!(DraftVersion::from_alpn(b"moqt-15"), Some(DraftVersion::Draft15));
        assert_eq!(DraftVersion::from_alpn(b"moqt-16"), Some(DraftVersion::Draft16));
        assert_eq!(DraftVersion::from_alpn(b"moqt-17"), Some(DraftVersion::Draft17));
        assert_eq!(DraftVersion::from_alpn(b"moqt-18"), Some(DraftVersion::Draft18));
    }

    #[test]
    fn from_alpn_none_for_moq_00_and_unknown() {
        assert_eq!(DraftVersion::from_alpn(b"moq-00"), None);
        assert_eq!(DraftVersion::from_alpn(b"h3"), None);
        assert_eq!(DraftVersion::from_alpn(b""), None);
        assert_eq!(DraftVersion::from_alpn(b"moqt-99"), None);
    }

    #[test]
    fn from_alpn_round_trips_with_quic_alpn() {
        for d in [
            DraftVersion::Draft15,
            DraftVersion::Draft16,
            DraftVersion::Draft17,
            DraftVersion::Draft18,
        ] {
            assert_eq!(DraftVersion::from_alpn(d.quic_alpn()), Some(d));
        }
    }

    #[test]
    fn from_number_resolves_supported_range() {
        for n in 7..=18u8 {
            assert!(DraftVersion::from_number(n).is_some(), "draft {n} should resolve");
        }
    }

    #[test]
    fn from_number_none_outside_range() {
        assert_eq!(DraftVersion::from_number(0), None);
        assert_eq!(DraftVersion::from_number(6), None);
        assert_eq!(DraftVersion::from_number(19), None);
        assert_eq!(DraftVersion::from_number(255), None);
    }
}

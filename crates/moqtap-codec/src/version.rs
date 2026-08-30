//! MoQT draft version enum for runtime dispatch.

use crate::varint::{Moqt17, Moqt18, VarInt, VarIntError};
use bytes::{Buf, BufMut};

/// A variable-length integer encoding used by some MoQT draft.
///
/// The MoQT variants are named for the draft that introduced each revision,
/// not for the drafts that use it — [`DraftVersion::varint_encoding`] is the
/// one place that maps drafts to encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarIntEncoding {
    /// The QUIC variable-length integer, RFC 9000 Section 16: a two-bit length
    /// prefix, 1/2/4/8 bytes, values up to 2^62 - 1.
    Rfc9000,
    /// MoQT's own, as introduced in draft-17 Section 1.4.1: the length is the
    /// number of leading 1 bits in the first byte. Draft-17 omits the 7-byte
    /// length and rejects that code point.
    Moqt17,
    /// MoQT's own, as revised in draft-18, which restored the 7-byte length so
    /// all of 1 to 9 bytes are defined.
    Moqt18,
}

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
    /// draft-ietf-moq-transport-19.
    Draft19,
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
            DraftVersion::Draft19 => 19,
        };
        VarInt::from_usize(0xff000000 + n as usize)
    }

    /// The ALPN protocol identifier for raw QUIC connections.
    ///
    /// Drafts 07–14 all use `moq-00` and negotiate the draft version in
    /// CLIENT_SETUP / SERVER_SETUP. Draft-15+ encode the draft number in the
    /// ALPN itself (`moqt-<N>`), so version selection happens during the TLS
    /// handshake rather than after it.
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
            DraftVersion::Draft19 => b"moqt-19",
        }
    }

    /// Resolve an ALPN identifier to a specific draft version.
    ///
    /// Returns `Some` for ALPNs that unambiguously identify a draft
    /// (`moqt-15`, `moqt-16`, `moqt-17`, `moqt-18`, `moqt-19`). Returns `None`
    /// for `moq-00` — which covers drafts 07–14 and requires inspecting
    /// CLIENT_SETUP's supported-versions list — and for any unrecognized
    /// ALPN.
    pub fn from_alpn(alpn: &[u8]) -> Option<DraftVersion> {
        match alpn {
            b"moqt-15" => Some(DraftVersion::Draft15),
            b"moqt-16" => Some(DraftVersion::Draft16),
            b"moqt-17" => Some(DraftVersion::Draft17),
            b"moqt-18" => Some(DraftVersion::Draft18),
            b"moqt-19" => Some(DraftVersion::Draft19),
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
            19 => Some(DraftVersion::Draft19),
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

    /// Which variable-length integer encoding this draft's wire format uses.
    ///
    /// Matched draft by draft rather than derived from the number. The series
    /// has already changed encoding once mid-stream and revised it again a
    /// draft later, so there is no rule to extrapolate from: adding a variant
    /// to [`DraftVersion`] must fail to compile here until someone reads that
    /// draft and says which encoding it uses.
    pub fn varint_encoding(&self) -> VarIntEncoding {
        match self {
            DraftVersion::Draft07
            | DraftVersion::Draft08
            | DraftVersion::Draft09
            | DraftVersion::Draft10
            | DraftVersion::Draft11
            | DraftVersion::Draft12
            | DraftVersion::Draft13
            | DraftVersion::Draft14
            | DraftVersion::Draft15
            | DraftVersion::Draft16 => VarIntEncoding::Rfc9000,
            DraftVersion::Draft17 => VarIntEncoding::Moqt17,
            DraftVersion::Draft18 | DraftVersion::Draft19 => VarIntEncoding::Moqt18,
        }
    }

    /// Whether this draft uses one of MoQT's own variable-length integers
    /// rather than RFC 9000's.
    pub fn uses_moqt_varint(&self) -> bool {
        self.varint_encoding() != VarIntEncoding::Rfc9000
    }

    /// The total encoded length of a variable-length integer, from its first
    /// byte, under this draft's encoding.
    ///
    /// Available without a buffer, because a reader needs it to know how many
    /// bytes to wait for before it can decode at all. On draft-17 a first byte
    /// of `11111100` reports 7 even though the draft forbids that length: the
    /// reader waits for the whole field, then [`Self::decode_varint`] rejects
    /// it.
    pub fn varint_len(&self, first_byte: u8) -> usize {
        match self.varint_encoding() {
            VarIntEncoding::Rfc9000 => 1 << (first_byte >> 6),
            VarIntEncoding::Moqt17 | VarIntEncoding::Moqt18 => {
                if first_byte == 0xFF {
                    9
                } else {
                    first_byte.leading_ones() as usize + 1
                }
            }
        }
    }

    /// Decode a variable-length integer under this draft's encoding.
    pub fn decode_varint(&self, buf: &mut impl Buf) -> Result<VarInt, VarIntError> {
        match self.varint_encoding() {
            VarIntEncoding::Rfc9000 => VarInt::decode(buf),
            VarIntEncoding::Moqt17 => VarInt::decode_moqt::<Moqt17>(buf),
            VarIntEncoding::Moqt18 => VarInt::decode_moqt::<Moqt18>(buf),
        }
    }

    /// Encode a variable-length integer under this draft's encoding.
    pub fn encode_varint(&self, value: VarInt, buf: &mut impl BufMut) {
        match self.varint_encoding() {
            VarIntEncoding::Rfc9000 => value.encode(buf),
            VarIntEncoding::Moqt17 => value.encode_moqt::<Moqt17>(buf),
            VarIntEncoding::Moqt18 => value.encode_moqt::<Moqt18>(buf),
        }
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
            DraftVersion::Draft19 => 19,
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

    /// The draft-to-encoding map, stated once so a change to it is a change to
    /// this list rather than a silent consequence of a comparison.
    #[test]
    fn every_draft_states_its_varint_encoding() {
        use VarIntEncoding::*;
        let expected = [
            (DraftVersion::Draft07, Rfc9000),
            (DraftVersion::Draft08, Rfc9000),
            (DraftVersion::Draft09, Rfc9000),
            (DraftVersion::Draft10, Rfc9000),
            (DraftVersion::Draft11, Rfc9000),
            (DraftVersion::Draft12, Rfc9000),
            (DraftVersion::Draft13, Rfc9000),
            (DraftVersion::Draft14, Rfc9000),
            (DraftVersion::Draft15, Rfc9000),
            (DraftVersion::Draft16, Rfc9000),
            (DraftVersion::Draft17, Moqt17),
            (DraftVersion::Draft18, Moqt18),
            (DraftVersion::Draft19, Moqt18),
        ];
        for (draft, encoding) in expected {
            assert_eq!(draft.varint_encoding(), encoding, "{draft}");
            assert_eq!(draft.uses_moqt_varint(), encoding != Rfc9000, "{draft}");
        }
    }

    /// The same value, in the encoding each era actually uses. 5000 is the
    /// interesting size: two bytes under both, with different bits.
    #[test]
    fn varint_len_and_round_trip_follow_the_encoding() {
        let mut buf = Vec::new();
        DraftVersion::Draft14.encode_varint(VarInt::from_usize(5000), &mut buf);
        assert_eq!(buf, vec![0x53, 0x88]);
        assert_eq!(DraftVersion::Draft14.varint_len(buf[0]), 2);

        let mut buf = Vec::new();
        DraftVersion::Draft19.encode_varint(VarInt::from_usize(5000), &mut buf);
        assert_eq!(buf, vec![0x93, 0x88]);
        assert_eq!(DraftVersion::Draft19.varint_len(buf[0]), 2);

        // 0x40 is a two-byte prefix under RFC 9000 and the one-byte value 64
        // from draft-17 on.
        assert_eq!(DraftVersion::Draft14.varint_len(0x40), 2);
        assert_eq!(DraftVersion::Draft19.varint_len(0x40), 1);
    }

    #[test]
    fn from_alpn_resolves_drafts_15_plus() {
        assert_eq!(DraftVersion::from_alpn(b"moqt-15"), Some(DraftVersion::Draft15));
        assert_eq!(DraftVersion::from_alpn(b"moqt-16"), Some(DraftVersion::Draft16));
        assert_eq!(DraftVersion::from_alpn(b"moqt-17"), Some(DraftVersion::Draft17));
        assert_eq!(DraftVersion::from_alpn(b"moqt-18"), Some(DraftVersion::Draft18));
        assert_eq!(DraftVersion::from_alpn(b"moqt-19"), Some(DraftVersion::Draft19));
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
            DraftVersion::Draft19,
        ] {
            assert_eq!(DraftVersion::from_alpn(d.quic_alpn()), Some(d));
        }
    }

    #[test]
    fn from_number_resolves_supported_range() {
        for n in 7..=19u8 {
            assert!(DraftVersion::from_number(n).is_some(), "draft {n} should resolve");
        }
    }

    #[test]
    fn from_number_none_outside_range() {
        assert_eq!(DraftVersion::from_number(0), None);
        assert_eq!(DraftVersion::from_number(6), None);
        assert_eq!(DraftVersion::from_number(20), None);
        assert_eq!(DraftVersion::from_number(255), None);
    }
}

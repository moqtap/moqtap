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
    /// draft-ietf-moq-transport-20.
    Draft20,
    /// draft-ietf-moq-transport-21.
    Draft21,
}

impl DraftVersion {
    /// Every draft of the series, oldest first.
    ///
    /// The variants are not feature-gated, so this is the whole series whatever
    /// the build compiles. It answers *which drafts exist*, which is a property
    /// of the specification; *which drafts this binary can decode* is a
    /// different question with a different answer per feature set, and
    /// `moqtap-proxy`'s `draft_is_compiled` is where that one lives.
    ///
    /// Sweeps should read this rather than write their own list. A written-out
    /// draft list is the most expensive silent defect this workspace has: it
    /// compiles, it passes, and it tests one draft fewer than it claims to.
    /// `shape/matcher.rs` shipped a `[DraftVersion; 13]` under a doc comment
    /// claiming the whole series, and every unit test that swept it stopped
    /// covering the newest draft without failing. A sweep over `ALL` cannot do
    /// that, and a sweep that deliberately covers *less* than the series -- one
    /// draft per era, or the drafts that have a joining fetch - still writes
    /// its own list and still says why.
    ///
    /// An array rather than a slice, so `for d in DraftVersion::ALL` yields
    /// drafts and not references and a caller can name the type. The length
    /// beside it is checked by the compiler against the contents, so it cannot
    /// silently disagree with them - and the contents are the half that goes
    /// wrong. `scripts/check-draft-parity.py` holds those against the enum, the
    /// per-draft source directories, the cargo features and the CI rows on
    /// every run, and the tests below hold them against `from_number`.
    pub const ALL: [DraftVersion; 15] = [
        DraftVersion::Draft07,
        DraftVersion::Draft08,
        DraftVersion::Draft09,
        DraftVersion::Draft10,
        DraftVersion::Draft11,
        DraftVersion::Draft12,
        DraftVersion::Draft13,
        DraftVersion::Draft14,
        DraftVersion::Draft15,
        DraftVersion::Draft16,
        DraftVersion::Draft17,
        DraftVersion::Draft18,
        DraftVersion::Draft19,
        DraftVersion::Draft20,
        DraftVersion::Draft21,
    ];

    /// The newest draft of the series.
    ///
    /// `ALL` is ordered, so this is its last element. Written as a method
    /// rather than left to the caller because `ALL.last().unwrap()` in a
    /// hundred places is a hundred unwraps, and because a caller that wants
    /// "the newest" almost always wants it infallibly.
    pub const fn newest() -> DraftVersion {
        // `ALL` is never empty, and a `const fn` cannot unwrap an `Option`, so
        // the index is written out. If `ALL` ever became empty this would fail
        // to compile rather than panic at run time.
        DraftVersion::ALL[DraftVersion::ALL.len() - 1]
    }

    /// The MoQT version number this draft would announce in CLIENT_SETUP.
    ///
    /// Format: `0xff000000 + draft_number`.
    ///
    /// **From draft-15 on there is no such value on the wire at all.** Draft-15
    /// deleted the version field from CLIENT_SETUP and moved version selection
    /// into the ALPN (`moqt-<N>`, see [`Self::quic_alpn`]), so the number this
    /// returns for drafts 15 through 21 — `0xff00000f` through `0xff000015` —
    /// is a continuation of the mapping and not something a peer can observe or
    /// send. Nothing in this crate encodes it for those drafts. It is kept so
    /// that a caller with a draft in hand can name the version the series would
    /// have used, and so the mapping does not acquire a hole.
    ///
    /// A tool that tries to detect the negotiated draft by looking for
    /// `0xff0000NN` in a capture will find nothing from draft-15 on; the ALPN is
    /// the only signal.
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
            DraftVersion::Draft20 => 20,
            DraftVersion::Draft21 => 21,
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
            DraftVersion::Draft20 => b"moqt-20",
            DraftVersion::Draft21 => b"moqt-21",
        }
    }

    /// Resolve an ALPN identifier to a specific draft version.
    ///
    /// Returns `Some` for ALPNs that unambiguously identify a draft
    /// (`moqt-15` through `moqt-21`). Returns `None`
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
            b"moqt-20" => Some(DraftVersion::Draft20),
            b"moqt-21" => Some(DraftVersion::Draft21),
            _ => None,
        }
    }

    /// Resolve a draft number (e.g. 7..=21) to a `DraftVersion`.
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
            20 => Some(DraftVersion::Draft20),
            21 => Some(DraftVersion::Draft21),
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
            // Draft-20 Section 1.4.1 is draft-18's encoding verbatim: the same
            // leading-ones-count prefix over all nine lengths. The revision
            // changed the hyphen in "Variable-length" in the heading and
            // nothing else about it. Draft-21 moved the section to 8.1 and
            // left the integer alone.
            DraftVersion::Draft18
            | DraftVersion::Draft19
            | DraftVersion::Draft20
            | DraftVersion::Draft21 => VarIntEncoding::Moqt18,
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

    /// The draft number (e.g. 7, 14, 21).
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
            DraftVersion::Draft20 => 20,
            DraftVersion::Draft21 => 21,
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

    /// `ALL` and `from_number` are two statements of the same set.
    ///
    /// Neither is derived from the other - one is a list of variants and the
    /// other a `match` over numbers - so they can disagree, and this is what
    /// says so. Adding a variant makes `number()` stop compiling, which is how
    /// the enum forces the first edit; this is what forces the rest.
    #[test]
    fn all_and_from_number_agree_on_which_drafts_exist() {
        let derived: Vec<DraftVersion> =
            (0u8..=255).filter_map(DraftVersion::from_number).collect();
        assert_eq!(
            DraftVersion::ALL.as_slice(),
            derived.as_slice(),
            "`DraftVersion::ALL` and `from_number` disagree about which drafts exist"
        );
    }

    /// Oldest first, with no gaps.
    ///
    /// Both halves are load-bearing for callers: the order is what makes
    /// `ALL.last()` the newest draft and `newest()` meaningful, and the
    /// contiguity is what lets a sweep say "every draft from N on" as a slice
    /// of `ALL` rather than a second list.
    #[test]
    fn all_is_ordered_and_contiguous() {
        for pair in DraftVersion::ALL.windows(2) {
            assert_eq!(
                pair[1].number(),
                pair[0].number() + 1,
                "`ALL` jumps from draft-{:02} to draft-{:02}",
                pair[0].number(),
                pair[1].number()
            );
        }
    }

    /// `newest()` is the last of `ALL`, and nothing is newer.
    #[test]
    fn newest_is_the_end_of_the_series() {
        assert_eq!(Some(DraftVersion::newest()), DraftVersion::ALL.last().copied());
        assert_eq!(
            DraftVersion::from_number(DraftVersion::newest().number() + 1),
            None,
            "a draft past the newest resolves, so `ALL` is short"
        );
    }

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
            (DraftVersion::Draft20, Moqt18),
            (DraftVersion::Draft21, Moqt18),
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
        DraftVersion::Draft20.encode_varint(VarInt::from_usize(5000), &mut buf);
        assert_eq!(buf, vec![0x93, 0x88]);
        assert_eq!(DraftVersion::Draft20.varint_len(buf[0]), 2);

        // 0x40 is a two-byte prefix under RFC 9000 and the one-byte value 64
        // from draft-17 on.
        assert_eq!(DraftVersion::Draft14.varint_len(0x40), 2);
        assert_eq!(DraftVersion::Draft20.varint_len(0x40), 1);
    }

    #[test]
    fn from_alpn_resolves_drafts_15_plus() {
        assert_eq!(DraftVersion::from_alpn(b"moqt-15"), Some(DraftVersion::Draft15));
        assert_eq!(DraftVersion::from_alpn(b"moqt-16"), Some(DraftVersion::Draft16));
        assert_eq!(DraftVersion::from_alpn(b"moqt-17"), Some(DraftVersion::Draft17));
        assert_eq!(DraftVersion::from_alpn(b"moqt-18"), Some(DraftVersion::Draft18));
        assert_eq!(DraftVersion::from_alpn(b"moqt-19"), Some(DraftVersion::Draft19));
        assert_eq!(DraftVersion::from_alpn(b"moqt-20"), Some(DraftVersion::Draft20));
        assert_eq!(DraftVersion::from_alpn(b"moqt-21"), Some(DraftVersion::Draft21));
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
        // Every draft with an ALPN of its own, off `ALL` rather than
        // listed: the cohort is "draft-15 onwards", and a list would have
        // to be extended by hand for each new draft to keep covering it.
        for d in DraftVersion::ALL.iter().copied().filter(|d| d.number() >= 15) {
            assert_eq!(DraftVersion::from_alpn(d.quic_alpn()), Some(d));
        }
    }

    #[test]
    fn from_number_resolves_supported_range() {
        for n in 7..=21u8 {
            assert!(DraftVersion::from_number(n).is_some(), "draft {n} should resolve");
        }
    }

    #[test]
    fn from_number_none_outside_range() {
        assert_eq!(DraftVersion::from_number(0), None);
        assert_eq!(DraftVersion::from_number(6), None);
        assert_eq!(DraftVersion::from_number(22), None);
        assert_eq!(DraftVersion::from_number(255), None);
    }
}

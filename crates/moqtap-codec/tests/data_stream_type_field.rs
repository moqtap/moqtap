//! The leading type field of a data stream and of a datagram, on the drafts
//! that carry it outside the header — 07 through 13.
//!
//! Every MoQT datagram opens with a variable-length integer naming its type,
//! and every unidirectional MOQT stream opens with one naming the stream's.
//! Drafts 14 and later fold that integer into the header struct, so their
//! encoders and decoders cannot leave it out. Drafts 07 through 13 model it
//! separately, and for a while nothing wrote it and nothing read it: the
//! draft-neutral entry point handed a received datagram's type octet to the
//! Track Alias field and shifted every field behind it by one, and the encoder
//! produced a datagram with no type at all.
//!
//! A round trip cannot find this and the vector corpus cannot either. A writer
//! that omits a field and a reader that does not expect it agree perfectly, and
//! the corpus for these drafts was generated from that pair. What finds it is a
//! frame built by hand from the draft's own field list, which is what every
//! fixture below is.
//!
//! The two halves are gated separately because they fail differently. A missing
//! stream type is a stream a peer refuses outright; a missing datagram type is
//! a datagram a peer accepts and misreads, which is the worse of the two and
//! the reason the datagram gates assert on the fields rather than only on the
//! refusal.
//!
//! # What breaking each fix does, observed by making the change and running
//!
//! The output quoted in each docstring came from making that edit and running
//! the test; none of it is a prediction.

#![cfg(all(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13"
))]

use moqtap_codec::dispatch::{AnyDatagramHeader, AnySubgroupHeader};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// `v` as QUIC varint bytes.
fn vb(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    VarInt::from_u64(v).expect("value fits a QUIC varint").encode(&mut out);
    out
}

/// Track Alias carried by every fixture below. Deliberately not 0 or 1: those
/// collide with the datagram type numbers, and a fixture whose type and alias
/// are interchangeable cannot tell a reader that swapped them from one that
/// did not.
const TRACK_ALIAS: u64 = 42;
/// Group ID carried by every fixture below.
const GROUP_ID: u64 = 7;
/// Object ID carried by every fixture below.
const OBJECT_ID: u64 = 3;
/// Publisher Priority carried by every fixture below.
const PRIORITY: u8 = 128;
/// The payload every payload-bearing fixture carries.
const PAYLOAD: &[u8] = b"PAYL";

/// The seven drafts that carry the type field outside the header.
const DRAFTS: &[DraftVersion] = &[
    DraftVersion::Draft07,
    DraftVersion::Draft08,
    DraftVersion::Draft09,
    DraftVersion::Draft10,
    DraftVersion::Draft11,
    DraftVersion::Draft12,
    DraftVersion::Draft13,
];

/// One draft's payload-bearing datagram, built from the draft's own field
/// list: type, then the header body, then the payload.
///
/// The layouts differ in three places. Drafts 07 and 08 declare the payload
/// length in the header; drafts 08 through 10 carry an extension field that
/// no type bit governs, so it is written as an explicit zero; drafts 11 through
/// 13 moved the extensions behind a bit in the type and this fixture leaves
/// that bit clear, which is why their header stops at the priority octet.
fn payload_datagram(draft: DraftVersion) -> Vec<u8> {
    let mut out = Vec::new();
    // 07-10 number the payload-bearing datagram 0x01; 11-13 number it 0x00
    // and spend the low bits on flags this fixture leaves clear.
    out.extend_from_slice(&vb(if draft.number() <= 10 { 0x01 } else { 0x00 }));
    out.extend_from_slice(&vb(TRACK_ALIAS));
    out.extend_from_slice(&vb(GROUP_ID));
    out.extend_from_slice(&vb(OBJECT_ID));
    out.push(PRIORITY);
    match draft.number() {
        7 => out.extend_from_slice(&vb(PAYLOAD.len() as u64)),
        8 => {
            out.extend_from_slice(&vb(0)); // extension count
            out.extend_from_slice(&vb(PAYLOAD.len() as u64));
        }
        9 | 10 => out.extend_from_slice(&vb(0)), // extension block length
        _ => {}
    }
    out.extend_from_slice(PAYLOAD);
    out
}

/// One draft's status datagram, or `None` for draft-07, which has no such
/// message: it states a status on the payload-bearing datagram by declaring a
/// payload length of zero.
///
/// The status is `0x3`, End of Group, which every draft here assigns.
fn status_datagram(draft: DraftVersion) -> Option<Vec<u8>> {
    if draft == DraftVersion::Draft07 {
        return None;
    }
    let mut out = Vec::new();
    // 08-11 number the status datagram 0x02. Drafts 12 and 13 spent 0x02 and
    // 0x03 on the End Of Group bit they added to the payload-bearing datagram
    // and moved the status to 0x04.
    out.extend_from_slice(&vb(if draft.number() <= 11 { 0x02 } else { 0x04 }));
    out.extend_from_slice(&vb(TRACK_ALIAS));
    out.extend_from_slice(&vb(GROUP_ID));
    out.extend_from_slice(&vb(OBJECT_ID));
    out.push(PRIORITY);
    if matches!(draft.number(), 9 | 10) {
        out.extend_from_slice(&vb(0)); // extension block length
    }
    out.extend_from_slice(&vb(0x03)); // object status: end of group
    Some(out)
}

/// A datagram's type field is consumed as a type, not as the first field of
/// the body.
///
/// The fixture's Track Alias is 42 and its type is 0 or 1, so a reader that
/// took the type for the alias would produce a header whose every field is one
/// field early and would stop one field short of the payload. The assertion is
/// on what is left in the buffer after the header: exactly the payload, and
/// nothing else.
///
/// # What breaking the fix does, observed by making the change and running
///
/// Pointing draft-11's `Datagram::decode` at `DatagramHeader::decode` without
/// consuming the type first, which is what the draft-neutral entry point used
/// to do on all seven:
///
/// ```text
/// assertion `left == right` failed: [draft-11] the header decode must stop at
/// the payload, leaving exactly it
///   left: 5
///  right: 4
/// ```
#[test]
fn a_datagram_type_is_read_as_a_type_and_not_as_a_track_alias() {
    for &draft in DRAFTS {
        let bytes = payload_datagram(draft);
        let mut cursor = &bytes[..];
        AnyDatagramHeader::decode(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] a well-formed datagram must decode: {e}"));
        assert_eq!(
            cursor.len(),
            PAYLOAD.len(),
            "[{draft}] the header decode must stop at the payload, leaving exactly it"
        );
        assert_eq!(cursor, PAYLOAD, "[{draft}] and the payload must arrive intact");
    }
}

/// A datagram written by the draft-neutral entry point is one a peer can read.
///
/// Byte-for-byte against the hand-built fixture, which shares no code with the
/// encoder: this is what makes the claim about the type field rather than about
/// the encoder agreeing with the decoder.
///
/// Both writers are driven. `AnyDatagramHeader::encode` dispatches to
/// `encode_checked`, so a gate that goes only through it says nothing about the
/// infallible `encode` beside it — which is the writer a caller reaches for
/// when it has no refusal to handle, and which could keep a headerless framing
/// to itself.
///
/// # What breaking the fix does, observed by making the change and running
///
/// Dropping the type field from draft-09's `Datagram::encode_checked`:
///
/// ```text
/// assertion `left == right` failed: [draft-09] the checked writer must write
/// the bytes a peer expects
///   left: "2a070380005041594c"
///  right: "012a070380005041594c"
/// ```
///
/// and from draft-09's infallible `Datagram::encode`, which the first
/// ablation leaves untouched:
///
/// ```text
/// assertion `left == right` failed: [draft-09] the infallible writer must
/// write the same bytes
///   left: "2a07038000"
///  right: "012a07038000"
/// ```
#[test]
fn a_datagram_is_written_with_the_type_field_it_was_read_with() {
    for &draft in DRAFTS {
        let bytes = payload_datagram(draft);
        let mut cursor = &bytes[..];
        let header = AnyDatagramHeader::decode(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] a well-formed datagram must decode: {e}"));

        let mut out = Vec::new();
        header
            .encode(&mut out)
            .unwrap_or_else(|e| panic!("[{draft}] and must be re-encodable: {e}"));
        let header_len = out.len();
        out.extend_from_slice(PAYLOAD);
        assert_eq!(
            hex::encode(&out),
            hex::encode(&bytes),
            "[{draft}] the checked writer must write the bytes a peer expects"
        );

        assert_eq!(
            hex::encode(encode_infallible(&header)),
            hex::encode(&bytes[..header_len]),
            "[{draft}] the infallible writer must write the same bytes"
        );
    }
}

/// A status datagram reaches the draft-neutral entry point at all.
///
/// Drafts 08 through 13 each define a second datagram message that states an
/// Object Status and carries no payload. The type field is what gives that
/// message a way through this entry point: without it every datagram decodes
/// as the payload-bearing one, so a status datagram arrives as an ordinary
/// object whose status octet has become part of its payload.
///
/// # What breaking the fix does, observed by making the change and running
///
/// Making draft-13's `Datagram::decode` ignore `is_status` and always take the
/// payload branch:
///
/// ```text
/// [draft-13] a status datagram must decode as one, and this decoded as a
/// payload datagram with 1 byte(s) left over
/// ```
#[test]
fn a_status_datagram_is_reachable_through_the_draft_neutral_entry_point() {
    for &draft in DRAFTS {
        let Some(bytes) = status_datagram(draft) else {
            assert_eq!(draft, DraftVersion::Draft07, "only draft-07 has no status datagram");
            continue;
        };
        let mut cursor = &bytes[..];
        let header = AnyDatagramHeader::decode(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] a well-formed status datagram must decode: {e}"));
        assert!(
            datagram_is_status(&header),
            "[{draft}] a status datagram must decode as one, and this decoded as a payload \
             datagram with {} byte(s) left over",
            cursor.len()
        );
        assert!(!cursor.has_remaining_bytes(), "[{draft}] a status datagram has no payload");

        let mut out = Vec::new();
        header
            .encode(&mut out)
            .unwrap_or_else(|e| panic!("[{draft}] and must be re-encodable: {e}"));
        assert_eq!(
            hex::encode(&out),
            hex::encode(&bytes),
            "[{draft}] the bytes written must be the bytes a peer expects"
        );
    }
}

/// Drafts 12 and 13 put End Of Group and Object Status at different type
/// numbers, and both put them where their type table says.
///
/// Those two drafts added an End Of Group bit to the payload-bearing datagram,
/// which took type numbers 0x02 and 0x03 and pushed the status datagram to 0x04
/// and 0x05. Each of them also still carries the sentence from the draft before
/// the bit existed, which puts the status datagram back at 0x02, and the two
/// cannot both be followed. Draft-14 keeps the table's answer and records the
/// sentence as a missed code-point update, so the table is the surviving half.
///
/// The consequence of following the other half is not a rejected datagram but
/// an accepted one: 0x02 read as a status type consumes the same fields in the
/// same order and then finds an Object Status where the payload begins. The
/// payload here is chosen so that it does — its first byte is 0x03, an assigned
/// status on both drafts — because a payload that happened to start with an
/// unassigned code would make the misread fail for a reason that says nothing
/// about the type numbering.
///
/// # What breaking the fix does, observed by making the change and running
///
/// Putting draft-12's `DatagramStatus` back at 0x02 and `DatagramStatusExt` at
/// 0x03, the numbers this codec carried before:
///
/// ```text
/// [draft-12] type 0x02 is a payload datagram that ends its group, and this
/// decoded as a status datagram
/// ```
#[test]
fn drafts_12_and_13_number_end_of_group_below_the_status_datagram() {
    // A payload whose first byte reads as an assigned Object Status, so a
    // datagram misread as a status datagram decodes rather than erroring.
    const STATUS_LIKE_PAYLOAD: &[u8] = &[0x03, 0xAA];

    for &draft in &[DraftVersion::Draft12, DraftVersion::Draft13] {
        // Type 0x02: a payload-bearing datagram that ends its group.
        let mut eog = vb(0x02);
        eog.extend_from_slice(&vb(TRACK_ALIAS));
        eog.extend_from_slice(&vb(GROUP_ID));
        eog.extend_from_slice(&vb(OBJECT_ID));
        eog.push(PRIORITY);
        eog.extend_from_slice(STATUS_LIKE_PAYLOAD);

        let mut cursor = &eog[..];
        let header = AnyDatagramHeader::decode(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] type 0x02 must decode: {e}"));
        assert!(
            !datagram_is_status(&header),
            "[{draft}] type 0x02 is a payload datagram that ends its group, and this decoded \
             as a status datagram"
        );
        assert_eq!(cursor, STATUS_LIKE_PAYLOAD, "[{draft}] and its payload must arrive intact");
        assert!(
            datagram_end_of_group(&header),
            "[{draft}] type 0x02 must carry the end of its group out to the caller"
        );

        // And the round trip puts it back at 0x02 rather than at 0x00.
        let mut out = Vec::new();
        header.encode(&mut out).unwrap_or_else(|e| panic!("[{draft}] must re-encode: {e}"));
        out.extend_from_slice(STATUS_LIKE_PAYLOAD);
        assert_eq!(
            hex::encode(&out),
            hex::encode(&eog),
            "[{draft}] the end of group must survive the round trip, and it lives in the type"
        );
    }
}

/// A subgroup stream can be written from its first byte, not only read from it.
///
/// `decode_stream` has existed on all fourteen drafts and consumes the leading
/// stream type; until now nothing wrote it back, so a caller opening a stream
/// with `encode` produced bytes that `decode_stream` reads with every field one
/// place late.
///
/// # What breaking the fix does, observed by making the change and running
///
/// Pointing draft-12's arm of `AnySubgroupHeader::encode_stream` at `encode`,
/// which is what a caller had to reach for before:
///
/// ```text
/// assertion `left == right` failed: [draft-12] the bytes written must be the
/// bytes a peer expects
///   left: "2a070380"
///  right: "142a070380"
/// ```
#[test]
fn a_subgroup_stream_can_be_written_from_its_first_byte() {
    for &draft in DRAFTS {
        // Build the header by reading one, so the fixture states the stream
        // type the way that draft spells it rather than the way this test
        // guesses.
        let opening = subgroup_stream_opening(draft);
        let mut cursor = &opening[..];
        let header = AnySubgroupHeader::decode_stream(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] the fixture must decode: {e}"));

        let mut out = Vec::new();
        header.encode_stream(&mut out);
        assert_eq!(
            hex::encode(&out),
            hex::encode(&opening),
            "[{draft}] the bytes written must be the bytes a peer expects"
        );

        let mut back = &out[..];
        let reread = AnySubgroupHeader::decode_stream(draft, &mut back);
        assert!(
            reread.is_ok(),
            "[{draft}] a stream written from its first byte must read back from its first \
             byte: {reread:?}"
        );
    }
}

/// One draft's subgroup stream opening: type, then the header body.
///
/// Drafts 07 through 10 have a single subgroup type, 0x04, and always carry an
/// explicit Subgroup ID. Drafts 11 through 13 spend a range of types on whether
/// the Subgroup ID is present and where it comes from; 0x0C and 0x14 are the
/// explicit-ID, no-extensions type on 11 and on 12/13 respectively.
fn subgroup_stream_opening(draft: DraftVersion) -> Vec<u8> {
    let stream_type: u64 = match draft.number() {
        7..=10 => 0x04,
        11 => 0x0C,
        _ => 0x14,
    };
    let mut out = vb(stream_type);
    out.extend_from_slice(&vb(TRACK_ALIAS));
    out.extend_from_slice(&vb(GROUP_ID));
    out.extend_from_slice(&vb(OBJECT_ID)); // subgroup id
    out.push(PRIORITY);
    out
}

/// The bytes each draft's infallible `Datagram::encode` writes.
///
/// The draft-neutral `AnyDatagramHeader::encode` goes through `encode_checked`,
/// so the writer beside it needs its own path to a gate.
fn encode_infallible(header: &AnyDatagramHeader) -> Vec<u8> {
    let mut out = Vec::new();
    match header {
        AnyDatagramHeader::Draft07(h) => h.encode(&mut out),
        AnyDatagramHeader::Draft08(h) => h.encode(&mut out),
        AnyDatagramHeader::Draft09(h) => h.encode(&mut out),
        AnyDatagramHeader::Draft10(h) => h.encode(&mut out),
        AnyDatagramHeader::Draft11(h) => h.encode(&mut out),
        AnyDatagramHeader::Draft12(h) => h.encode(&mut out),
        AnyDatagramHeader::Draft13(h) => h.encode(&mut out),
        other => panic!("{other:?} is not one of the seven drafts this file is about"),
    }
    out
}

/// Whether a decoded datagram states an Object Status rather than a payload.
fn datagram_is_status(header: &AnyDatagramHeader) -> bool {
    match header {
        AnyDatagramHeader::Draft07(h) => h.is_status(),
        AnyDatagramHeader::Draft08(h) => h.is_status(),
        AnyDatagramHeader::Draft09(h) => h.is_status(),
        AnyDatagramHeader::Draft10(h) => h.is_status(),
        AnyDatagramHeader::Draft11(h) => h.is_status(),
        AnyDatagramHeader::Draft12(h) => h.is_status(),
        AnyDatagramHeader::Draft13(h) => h.is_status(),
        other => panic!("{other:?} is not one of the seven drafts this file is about"),
    }
}

/// Whether a decoded draft-12 or draft-13 datagram carries the end of its
/// group, which those two drafts state in the type field and nowhere else.
fn datagram_end_of_group(header: &AnyDatagramHeader) -> bool {
    use moqtap_codec::draft12::data_stream::Datagram as D12;
    use moqtap_codec::draft13::data_stream::Datagram as D13;
    match header {
        AnyDatagramHeader::Draft12(D12::Payload(h)) => h.end_of_group,
        AnyDatagramHeader::Draft13(D13::Payload(h)) => h.end_of_group,
        other => panic!("{other:?} is not a draft-12 or draft-13 payload datagram"),
    }
}

/// `Buf::has_remaining` under a name that says what is left.
trait Remaining {
    fn has_remaining_bytes(&self) -> bool;
}

impl Remaining for &[u8] {
    fn has_remaining_bytes(&self) -> bool {
        !self.is_empty()
    }
}

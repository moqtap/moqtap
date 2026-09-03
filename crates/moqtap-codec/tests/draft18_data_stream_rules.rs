//! The rules draft-18 states about data stream and datagram framing, driven
//! from bytes.
//!
//! Each test here restates one rule from the draft in its own terms — an
//! enumerated list of Type values, a sentence about what may follow a header —
//! and then asks the codec for the consequence: does this frame decode, and
//! what does the decoded value say. Nothing reads a setting back.
//!
//! The Type-value tables in particular are written from the draft's own
//! enumerations rather than from the masks the codec uses, so a mask that
//! drifted would fail here instead of agreeing with itself.

#![cfg(feature = "draft18")]

use bytes::Buf;
use moqtap_codec::draft18::data_stream::{
    DatagramHeader, EndOfRange, FetchObjectHeader, FetchObjectReader, GroupOrder,
    PayloadPermission, SubgroupHeader, SubgroupObjectReader, PADDING_DATAGRAM_TYPE,
    PADDING_STREAM_TYPE,
};
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::{Moqt18 as Wire, VarInt};

/// Encode `v` as a draft-18 variable-length integer.
fn varint(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    VarInt::from_u64_moqt(v).encode_moqt::<Wire>(&mut out);
    out
}

// ── Type values ─────────────────────────────────────────────

/// The subgroup stream Type values draft-18 Section 11.4.2 allows, written
/// from the section rather than from the codec's masks.
///
/// The section gives the form as four ranges — "0x10 to 0x1F, 0x30 to 0x3F,
/// 0x50 to 0x5F, 0x70 to 0x7F" — and then lists sixteen values inside them
/// that are invalid because SUBGROUP_ID_MODE is 0b11.
fn draft_allows_subgroup_type(header_type: u8) -> bool {
    const RESERVED_MODE: &[u8] = &[
        0x16, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F, 0x56, 0x57, 0x5E, 0x5F, 0x76, 0x77, 0x7E,
        0x7F,
    ];
    let in_form = matches!(header_type, 0x10..=0x1F | 0x30..=0x3F | 0x50..=0x5F | 0x70..=0x7F);
    in_form && !RESERVED_MODE.contains(&header_type)
}

/// A subgroup header with the fields `header_type` announces: track alias 1,
/// group 0, an explicit subgroup ID of 0 when the mode calls for one, and
/// priority 128 unless DEFAULT_PRIORITY suppresses it.
fn subgroup_header_bytes(header_type: u8) -> Vec<u8> {
    let mut out = vec![header_type, 0x01, 0x00];
    if (header_type & 0x06) >> 1 == 2 {
        out.push(0x00);
    }
    if header_type & 0x20 == 0 {
        out.push(0x80);
    }
    out
}

/// Every octet the draft rules out is refused, and every octet it allows
/// decodes.
///
/// The sweep is every one-byte Type, so it covers the two invalid lists
/// together: the sixteen reserved-mode types inside the form, and everything
/// outside it below 0x80.
///
/// It stops at 0x7F because that is where one byte stops being one Type. A
/// first byte of 0x80 or above announces a longer MoQT variable-length integer,
/// so the bytes behind it belong to the Type rather than to the header — which
/// is exactly how a padding stream arrives, its Type leading with 0xF0. Those
/// are gated by [`a_type_wider_than_one_byte_is_refused_by_what_it_is`], which
/// has to supply whole fields rather than single bytes.
///
/// # Ablation
///
/// Reverting `SubgroupHeader::decode` to the bit-4 test it had before —
/// `header_type & SUBGROUP_BASE_BIT == 0` in place of the
/// `subgroup_type_is_valid` call — was run and gives:
///
/// ```text
/// thread 'a_subgroup_stream_refuses_every_type_value_the_draft_calls_invalid'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:100:26:
/// draft-18 Section 11.4.2 lists type 0x16 as invalid, but it decoded
/// ```
#[test]
fn a_subgroup_stream_refuses_every_type_value_the_draft_calls_invalid() {
    for header_type in 0x00u8..=0x7F {
        let bytes = subgroup_header_bytes(header_type);
        let result = SubgroupHeader::decode(&mut &bytes[..]);

        if draft_allows_subgroup_type(header_type) {
            let header = result.unwrap_or_else(|e| {
                panic!(
                    "draft-18 Section 11.4.2 allows type {header_type:#04x}, \
                     but it was refused: {e}"
                )
            });
            assert_eq!(
                header.header_type, header_type,
                "type {header_type:#04x} came back as another type"
            );
        } else {
            match result {
                Ok(_) => panic!(
                    "draft-18 Section 11.4.2 lists type {header_type:#04x} as invalid, \
                     but it decoded"
                ),
                Err(e) => assert_refusal(header_type, &e, expected_subgroup_refusal(header_type)),
            }
        }
    }
}

/// The checked encoder writes only the Type values the decoder accepts.
///
/// A Type value the draft calls invalid is not merely unreadable by this
/// module: Section 11.4.2 answers one with "MUST close the session with a
/// PROTOCOL_VIOLATION", so a stream opened with one costs the session rather
/// than the stream. Refusing before the first byte is written keeps the
/// rejected header out of the buffer entirely.
///
/// # Ablation
///
/// Dropping the type check from `SubgroupHeader::encode_checked` was run and
/// gives:
///
/// ```text
/// thread 'the_checked_subgroup_encoder_writes_only_what_the_decoder_accepts'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:147:13:
/// encode_checked wrote type 0x00, which Section 11.4.2 calls invalid
/// ```
#[test]
fn the_checked_subgroup_encoder_writes_only_what_the_decoder_accepts() {
    for header_type in 0x00u8..=0xFF {
        let bytes = subgroup_header_bytes(header_type);
        let Ok(header) = SubgroupHeader::decode(&mut &bytes[..]) else {
            // A header this module cannot read cannot be built from the wire
            // either, so the encode side is reached through a hand-built one.
            let header = SubgroupHeader {
                header_type,
                track_alias: VarInt::from_u64_moqt(1),
                group_id: VarInt::from_u64_moqt(0),
                subgroup_id: VarInt::from_u64_moqt(0),
                publisher_priority: Some(0x80),
            };
            let mut written = Vec::new();
            let outcome = header.encode_checked(&mut written);
            assert_refusal(
                header_type,
                &outcome.expect_err(&format!(
                    "encode_checked wrote type {header_type:#04x}, \
                     which Section 11.4.2 calls invalid"
                )),
                expected_subgroup_refusal(header_type),
            );
            assert!(
                written.is_empty(),
                "a refused type {header_type:#04x} still wrote {written:02x?}"
            );
            continue;
        };

        let mut written = Vec::new();
        header
            .encode_checked(&mut written)
            .unwrap_or_else(|e| panic!("encode_checked refused type {header_type:#04x}: {e}"));
        assert_eq!(written, bytes, "type {header_type:#04x} did not re-encode to its own bytes");
    }
}

/// The datagram Type values draft-18 Section 11.3.1 allows, written from the
/// section rather than from the codec's masks.
///
/// The form gives "the ranges 0x00..0x0F and 0x20..0x2F", and the section then
/// lists the eight values inside them that set both the STATUS bit and the
/// END_OF_GROUP bit.
fn draft_allows_datagram_type(datagram_type: u8) -> bool {
    const STATUS_AND_END_OF_GROUP: &[u8] = &[0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F];
    let in_form = matches!(datagram_type, 0x00..=0x0F | 0x20..=0x2F);
    in_form && !STATUS_AND_END_OF_GROUP.contains(&datagram_type)
}

/// One of the three shapes a refused Type can take on drafts 16 through 20.
///
/// The sweeps below would pass on "some error", and that is what is worth not
/// settling for: these are three different rules, and only two of them end the
/// session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// A Type no table assigns. Section 3.4 ends the session.
    Unknown,
    /// A Type inside a form the draft defines but on a list it calls invalid.
    /// Sections 11.4.2 and 11.3.1 end the session and name the code.
    NamedInvalid,
    /// A Type the draft assigns, handed to a reader that cannot read it. The
    /// session survives.
    NotThisReader,
}

/// Which answer a refused subgroup Type deserves.
fn expected_subgroup_refusal(header_type: u8) -> Refusal {
    const RESERVED_MODE: &[u8] = &[
        0x16, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F, 0x56, 0x57, 0x5E, 0x5F, 0x76, 0x77, 0x7E,
        0x7F,
    ];
    if header_type == 0x05 {
        // FETCH_HEADER, which Table 3 assigns.
        Refusal::NotThisReader
    } else if RESERVED_MODE.contains(&header_type) {
        Refusal::NamedInvalid
    } else {
        Refusal::Unknown
    }
}

/// Which answer a refused datagram Type deserves.
fn expected_datagram_refusal(datagram_type: u8) -> Refusal {
    const STATUS_AND_END_OF_GROUP: &[u8] = &[0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F];
    if STATUS_AND_END_OF_GROUP.contains(&datagram_type) {
        Refusal::NamedInvalid
    } else {
        Refusal::Unknown
    }
}

fn assert_refusal(ty: u8, got: &CodecError, want: Refusal) {
    let ok = match want {
        Refusal::Unknown => {
            matches!(got, CodecError::UnknownStreamType(_) | CodecError::UnknownDatagramType(_))
        }
        Refusal::NamedInvalid => matches!(got, CodecError::InvalidTypeValue { .. }),
        Refusal::NotThisReader => matches!(got, CodecError::InvalidField),
    };
    assert!(ok, "type {ty:#04x} was refused with {got:?}, which is not {want:?}");
}

/// A datagram with the fields `datagram_type` announces: track alias 1, group
/// 0, object 0, priority 128, a two-byte property block and a Normal status,
/// each present only when its bit is set.
fn datagram_bytes(datagram_type: u8) -> Vec<u8> {
    let mut out = vec![datagram_type, 0x01, 0x00];
    if datagram_type & 0x04 == 0 {
        out.push(0x00);
    }
    if datagram_type & 0x08 == 0 {
        out.push(0x80);
    }
    if datagram_type & 0x01 != 0 {
        out.extend_from_slice(&[0x02, 0x3C, 0x02]);
    }
    if datagram_type & 0x20 != 0 {
        out.push(0x00);
    }
    out
}

/// Every octet the draft rules out is refused, and every octet it allows
/// decodes.
///
/// # Ablation
///
/// Removing the `datagram_type_is_valid` call from `DatagramHeader::decode`
/// was run and gives:
///
/// ```text
/// thread 'a_datagram_refuses_every_type_value_the_draft_calls_invalid'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:231:26:
/// draft-18 Section 11.3.1 lists type 0x10 as invalid, but it decoded
/// ```
#[test]
fn a_datagram_refuses_every_type_value_the_draft_calls_invalid() {
    for datagram_type in 0x00u8..=0x7F {
        let bytes = datagram_bytes(datagram_type);
        let result = DatagramHeader::decode(&mut &bytes[..]);

        if draft_allows_datagram_type(datagram_type) {
            let header = result.unwrap_or_else(|e| {
                panic!(
                    "draft-18 Section 11.3.1 allows type {datagram_type:#04x}, \
                     but it was refused: {e}"
                )
            });
            assert_eq!(
                header.datagram_type, datagram_type,
                "type {datagram_type:#04x} came back as another type"
            );
        } else {
            match result {
                Ok(_) => panic!(
                    "draft-18 Section 11.3.1 lists type {datagram_type:#04x} as invalid, \
                     but it decoded"
                ),
                Err(e) => {
                    assert_refusal(datagram_type, &e, expected_datagram_refusal(datagram_type))
                }
            }
        }
    }
}

/// The checked encoder writes only the Type values the decoder accepts.
///
/// Section 11.3.1 answers an invalid Type with "MUST close the session with a
/// PROTOCOL_VIOLATION", so the cost of writing one is the session. The status
/// rule `encode_checked` already applied is unaffected: this adds the type rule
/// beside it.
///
/// # Ablation
///
/// Dropping the type check from `DatagramHeader::encode_checked` was run and
/// gives:
///
/// ```text
/// thread 'the_checked_datagram_encoder_writes_only_what_the_decoder_accepts'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:290:13:
/// encode_checked wrote type 0x10, which Section 11.3.1 calls invalid
/// ```
#[test]
fn the_checked_datagram_encoder_writes_only_what_the_decoder_accepts() {
    for datagram_type in 0x00u8..=0xFF {
        let bytes = datagram_bytes(datagram_type);
        let header = match DatagramHeader::decode(&mut &bytes[..]) {
            Ok(header) => header,
            Err(_) => DatagramHeader {
                datagram_type,
                track_alias: VarInt::from_u64_moqt(1),
                group_id: VarInt::from_u64_moqt(0),
                object_id: VarInt::from_u64_moqt(0),
                publisher_priority: Some(0x80),
                properties: Vec::new(),
                object_status: None,
            },
        };

        let mut written = Vec::new();
        let outcome = header.encode_checked(&mut written);

        if draft_allows_datagram_type(datagram_type) {
            outcome.unwrap_or_else(|e| {
                panic!("encode_checked refused type {datagram_type:#04x}: {e}")
            });
            assert_eq!(
                written, bytes,
                "type {datagram_type:#04x} did not re-encode to its own bytes"
            );
        } else {
            assert_refusal(
                datagram_type,
                &outcome.expect_err(&format!(
                    "encode_checked wrote type {datagram_type:#04x}, \
                     which Section 11.3.1 calls invalid"
                )),
                expected_datagram_refusal(datagram_type),
            );
            assert!(
                written.is_empty(),
                "a refused type {datagram_type:#04x} still wrote {written:02x?}"
            );
        }
    }
}

// ── Padding ─────────────────────────────────────────────────

/// A padding frame is refused, rather than read as a header.
///
/// Draft-18 Section 11.5.1 gives padding a stream type and a datagram type of
/// its own, carrying "zero or more bytes that MUST all be set to zero" and no
/// Objects at all. Under the draft-18 variable-length integer encoding both
/// values lead with 0xF0, an octet that sets bit 4 — so a decoder testing only
/// that bit reads a padding stream as a subgroup header and invents a track
/// alias and group ID from the type's own remaining bytes. This asserts the
/// leading octet as well as the refusal, because the refusal is only
/// interesting given what that octet used to mean.
///
/// # Ablation
///
/// Reverting `SubgroupHeader::decode` to the bit-4 test was run and gives:
///
/// ```text
/// thread 'a_padding_frame_is_refused_rather_than_read_as_a_header'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:351:23:
/// a padding stream decoded as a subgroup header: track alias 19, group 43
/// ```
///
/// Removing the type check from `DatagramHeader::decode` gives the other half:
///
/// ```text
/// thread 'a_padding_frame_is_refused_rather_than_read_as_a_header'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:365:23:
/// a padding datagram decoded as a datagram header: track alias 19, group 43
/// ```
///
/// The 19 and 43 are the padding type's own third and fourth octets, read as a
/// Track Alias and a Group ID — the invented header this refusal replaces.
#[test]
fn a_padding_frame_is_refused_rather_than_read_as_a_header() {
    let stream_type = varint(PADDING_STREAM_TYPE);
    let datagram_type = varint(PADDING_DATAGRAM_TYPE);
    assert_eq!(
        stream_type,
        vec![0xF0, 0x13, 0x2B, 0x3E, 0x28],
        "the padding stream type's encoding is what makes this case reachable"
    );
    assert_eq!(datagram_type, vec![0xF0, 0x13, 0x2B, 0x3E, 0x29]);

    // Padding data: the draft says every byte of it is zero.
    let mut stream = stream_type.clone();
    stream.extend_from_slice(&[0x00; 8]);
    match SubgroupHeader::decode(&mut &stream[..]) {
        Ok(header) => panic!(
            "a padding stream decoded as a subgroup header: track alias {}, group {}",
            header.track_alias.into_inner(),
            header.group_id.into_inner()
        ),
        Err(e) => assert!(
            matches!(e, CodecError::InvalidField),
            "Table 3 assigns the padding stream type, so it must be refused without naming \
             the unknown-stream-type rule that would end the session, got {e:?}"
        ),
    }

    let mut datagram = datagram_type.clone();
    datagram.extend_from_slice(&[0x00; 8]);
    match DatagramHeader::decode(&mut &datagram[..]) {
        Ok(header) => panic!(
            "a padding datagram decoded as a datagram header: track alias {}, group {}",
            header.track_alias.into_inner(),
            header.group_id.into_inner()
        ),
        Err(e) => assert!(
            matches!(e, CodecError::InvalidField),
            "the padding datagram type is assigned, so it must be refused without naming \
             the unknown-datagram-type rule that would end the session, got {e:?}"
        ),
    }
}

/// A Type wider than one byte is refused, and refused as what it actually is.
///
/// No subgroup header or datagram has a multi-byte Type, so every case here is
/// a refusal — but not the same refusal, and that is the point. Table 3 assigns
/// four Types and two of them are several bytes wide: SETUP at 0x2F00 and
/// PADDING at 0x132B3E28. A data reader handed either must not report it under
/// a rule about Types the draft does not have, because that rule ends the
/// session — over the peer's control stream in the first case and over traffic
/// Section 11.5.1 explicitly permits in the second.
///
/// The padding halves of that live in
/// [`a_padding_frame_is_refused_rather_than_read_as_a_header`]. What is here is
/// SETUP, a wide Type no table assigns, and the reason a Type is decoded rather
/// than narrowed: a two-byte 0x8010 carries the value 0x10, an assigned subgroup
/// Type, and its low octet is 0x10 as well, so a decoder that truncated would
/// read it as a valid header.
///
/// # Ablation
///
/// Removed the `wide_type_refusal` call from `SubgroupHeader::decode`, leaving
/// the one-byte read:
///
/// ```text
/// thread 'a_type_wider_than_one_byte_is_refused_by_what_it_is' (48484) panicked at
/// crates\moqtap-codec\tests\draft18_data_stream_rules.rs:470:19:
/// SETUP is a Type Table 3 assigns, so a subgroup reader must refuse it without naming the unknown-stream-type rule, got UnknownStreamType(175)
/// ```
///
/// The same ablation fires
/// [`a_padding_frame_is_refused_rather_than_read_as_a_header`] with the case
/// that costs more:
///
/// ```text
/// Table 3 assigns the padding stream type, so it must be refused without naming the unknown-stream-type rule that would end the session, got UnknownStreamType(240)
/// ```
///
/// 175 and 240 are 0xAF and 0xF0, the first bytes of the two wide Types — so
/// the reader both ended the session over an assigned stream and named a number
/// the peer never sent.
#[test]
fn a_type_wider_than_one_byte_is_refused_by_what_it_is() {
    let mut setup = varint(0x2F00);
    setup.extend_from_slice(&[0x01, 0x00, 0x07, 0x80]);
    match SubgroupHeader::decode(&mut &setup[..]) {
        Ok(h) => panic!("SETUP is not a subgroup header, but decode accepted {h:?}"),
        Err(e) => assert!(
            matches!(e, CodecError::InvalidField),
            "SETUP is a Type Table 3 assigns, so a subgroup reader must refuse it without \
             naming the unknown-stream-type rule, got {e:?}"
        ),
    }

    let mut unassigned = varint(0x0100);
    unassigned.extend_from_slice(&[0x01, 0x00, 0x07, 0x80]);
    match SubgroupHeader::decode(&mut &unassigned[..]) {
        Ok(h) => panic!("0x0100 is not a Type draft-18 assigns, but decode accepted {h:?}"),
        Err(e) => assert!(
            matches!(e, CodecError::UnknownStreamType(0x0100)),
            "a Type no table assigns must be named as unknown, got {e:?}"
        ),
    }

    let non_minimal = [0x80u8, 0x10, 0x01, 0x00, 0x07, 0x80];
    assert!(
        SubgroupHeader::decode(&mut &non_minimal[..]).is_err(),
        "a wide spelling must not be narrowed onto the assigned Type 0x10"
    );
}

// ── A status datagram carries no payload ────────────────────

/// A datagram whose type byte sets the STATUS bit may not be followed by
/// anything — whatever status it carries.
///
/// Draft-18 Section 11.3.1: "When set to 1, the Object Status field is present
/// and there is no Object Payload." The bytes after such a header are not a
/// short payload — there is no payload field for them to be — so they are
/// refused rather than delivered.
///
/// Normal is the case a status-based rule misses, and the one this exists for.
/// Section 11.2.1.1 permits a payload to a Normal object, so a predicate that
/// asks only about the status reports that a status datagram carrying Normal
/// may be followed by a payload, and the bytes behind it reach the application
/// as one. The framing answers first, and every row here is checked through
/// `permits_payload` as well as through the decoder, so the two cannot drift.
///
/// # Ablation
///
/// Reverting `permits_payload` to the status-only test — dropping its leading
/// `if self.has_status() { return false; }` — was run and gives:
///
/// ```text
/// thread 'a_status_datagram_may_not_be_followed_by_payload_bytes'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:437:9:
/// status 0x0: a datagram with no payload field permits no payload
/// ```
///
/// Dropping the refusal from `decode_object` instead, so the predicate stands
/// but nothing consults it:
///
/// ```text
/// thread 'a_status_datagram_may_not_be_followed_by_payload_bytes'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:443:22:
/// status 0x0: decode_object accepted 4 byte(s) after a header with no payload field
/// ```
#[test]
fn a_status_datagram_may_not_be_followed_by_payload_bytes() {
    // Type 0x20: STATUS bit set, explicit object ID, explicit priority.
    let status_datagram = |status: u8, tail: &[u8]| {
        let mut out = vec![0x20, 0x01, 0x00, 0x00, 0x80, status];
        out.extend_from_slice(tail);
        out
    };

    for status in [0x00u8, 0x03, 0x04] {
        let bytes = status_datagram(status, &[0xDE, 0xAD, 0xBE, 0xEF]);

        // The header-only decoder still reads it and hands the tail back: it
        // has no way to know whether those bytes are this datagram's or the
        // caller's next frame.
        let mut cursor = &bytes[..];
        let header = DatagramHeader::decode(&mut cursor)
            .unwrap_or_else(|e| panic!("status {status:#x}: the header must still decode: {e}"));
        assert!(header.has_status(), "status {status:#x}: the STATUS bit was not read");
        assert_eq!(
            cursor.remaining(),
            4,
            "status {status:#x}: the tail must be left in the buffer"
        );
        assert!(
            !header.permits_payload(),
            "status {status:#x}: a datagram with no payload field permits no payload"
        );

        match DatagramHeader::decode_object(&mut &bytes[..]) {
            Ok(_) => panic!(
                "status {status:#x}: decode_object accepted 4 byte(s) after a header \
                 with no payload field"
            ),
            Err(e) => assert!(
                matches!(e, CodecError::PayloadNotPermitted { .. }),
                "status {status:#x}: the trailing bytes were refused as {e}, \
                 not as bytes the frame does not define"
            ),
        }

        // With nothing after it the same datagram is well formed.
        let bytes = status_datagram(status, &[]);
        let (_, payload) = DatagramHeader::decode_object(&mut &bytes[..]).unwrap_or_else(|e| {
            panic!("status {status:#x}: a status datagram with no tail must decode: {e}")
        });
        assert!(payload.is_empty(), "status {status:#x}: a status datagram has no payload");
    }

    // A datagram framed for a payload keeps it. Type 0x00: no STATUS bit.
    let bytes: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x80, 0xDE, 0xAD, 0xBE, 0xEF];
    let (header, payload) = DatagramHeader::decode_object(&mut &bytes[..])
        .expect("a payload datagram must keep its payload");
    assert!(!header.has_status());
    assert!(header.permits_payload());
    assert_eq!(payload, vec![0xDE, 0xAD, 0xBE, 0xEF], "the payload must be handed back");
}

// ── Payload permission ──────────────────────────────────────

/// A subgroup object's framing reports whether the draft allowed it a payload.
///
/// Draft-18 Section 11.2.1.1: "Any object with a status code other than zero
/// MUST have an empty payload", and Normal "is implicit for any non-zero length
/// object". So the two objects on this stream answer differently, and neither
/// answer is read off a field that was set by hand: both come from bytes.
///
/// The stream is `subgroup-object-status-end-of-group` from the draft-18
/// corpus: a four-byte object, then a zero-length one carrying End of Group.
///
/// # Ablation
///
/// Answering `Some(PayloadPermission::Permitted)` for every status was run and
/// gives:
///
/// ```text
/// thread 'a_subgroup_object_meta_reports_the_payload_rule'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:514:5:
/// assertion `left == right` failed: an End of Group object may not carry a payload
///   left: Some(Permitted)
///  right: Some(Forbidden)
/// ```
#[test]
fn a_subgroup_object_meta_reports_the_payload_rule() {
    let bytes: &[u8] =
        &[0x10, 0x01, 0x00, 0x80, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x03];
    let mut cursor = bytes;
    let header = SubgroupHeader::decode(&mut cursor).expect("the header parses");
    let mut reader = SubgroupObjectReader::new(&header);

    let payload_object = reader.read_object_meta(&mut cursor).expect("the first object parses");
    assert_eq!(payload_object.payload_length, 4);
    assert_eq!(
        payload_object.payload_permission(),
        Some(PayloadPermission::Permitted),
        "an object that carries bytes is Normal, and Normal permits them"
    );
    assert!(payload_object.payload_permission().is_some_and(PayloadPermission::permits));

    let status_object = reader.read_object_meta(&mut cursor).expect("the second object parses");
    assert_eq!(status_object.status, Some(3));
    assert_eq!(
        status_object.payload_permission(),
        Some(PayloadPermission::Forbidden),
        "an End of Group object may not carry a payload"
    );
    assert!(!status_object.payload_permission().is_some_and(PayloadPermission::permits));

    // A status the draft never assigned has no rule to report. No stream can
    // produce this — `read_object_meta` refuses an unassigned code — so it is
    // built here to pin the third answer.
    let unassigned = moqtap_codec::draft18::data_stream::SubgroupObjectMeta {
        status: Some(0x2),
        ..status_object
    };
    assert_eq!(
        unassigned.payload_permission(),
        None,
        "draft-18 assigns no 0x2, so it states no payload rule for one"
    );
}

// ── Delta wrap ──────────────────────────────────────────────

/// An Object ID Delta that would push the ID past 2^64 - 1 is reported as its
/// own error, not as one malformation among many.
///
/// Draft-18 Section 11.4.2: "The Object ID Delta + 1 is added to the previous
/// Object ID in the Subgroup stream if there was one... If the resulting Object
/// ID would be greater than 2^64 - 1, the endpoint MUST close the session with
/// a PROTOCOL_VIOLATION." A session can only be closed for a reason its holder
/// can recognise, so the distinct variant is the part of that rule this crate
/// can carry: `InvalidField` is shared with a dozen unrelated malformations
/// that the draft does not answer with a close.
///
/// The stream is an object with delta 0 followed by one with delta 2^64 - 1, so
/// the sum overflows on the second object rather than on the first.
///
/// # Ablation
///
/// Replacing the `ObjectIdOverflow` in `read_object` and `read_object_meta`
/// with `InvalidField` was run and gives:
///
/// ```text
/// thread 'a_wrapped_object_id_delta_is_reported_as_its_own_error'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:582:19:
/// read_object reported a wrapped Object ID as invalid field value, which a session cannot act on
/// ```
#[test]
fn a_wrapped_object_id_delta_is_reported_as_its_own_error() {
    let mut bytes = vec![0x10, 0x01, 0x00, 0x80];
    bytes.extend_from_slice(&varint(0)); // first object: delta 0, so Object ID 0
    bytes.extend_from_slice(&varint(1));
    bytes.push(0xAA);
    bytes.extend_from_slice(&varint(u64::MAX)); // second object: the wrap
    bytes.extend_from_slice(&varint(1));
    bytes.push(0xBB);

    let mut cursor = &bytes[..];
    let header = SubgroupHeader::decode(&mut cursor).expect("the header parses");
    let objects = cursor;

    let mut reader = SubgroupObjectReader::new(&header);
    let mut cursor = objects;
    reader.read_object(&mut cursor).expect("the first object parses");
    match reader.read_object(&mut cursor) {
        Ok(object) => {
            panic!("read_object resolved a wrapped Object ID to {}", object.object_id.into_inner())
        }
        Err(e) => assert!(
            matches!(e, CodecError::ObjectIdOverflow(0, u64::MAX)),
            "read_object reported a wrapped Object ID as {e}, which a session cannot act on"
        ),
    }

    let mut reader = SubgroupObjectReader::new(&header);
    let mut cursor = objects;
    reader.read_object_meta(&mut cursor).expect("the first object parses");
    match reader.read_object_meta(&mut cursor) {
        Ok(meta) => panic!("read_object_meta resolved a wrapped Object ID to {}", meta.object_id),
        Err(e) => assert!(
            matches!(e, CodecError::ObjectIdOverflow(0, u64::MAX)),
            "read_object_meta reported a wrapped Object ID as {e}, which a session cannot act on"
        ),
    }
}

// ── Fetch objects ───────────────────────────────────────────

/// A fetch stream's first Object must state everything it is, since there is no
/// Object before it to inherit from.
///
/// Draft-18 Section 11.4.4.1: "The first Object MUST include a Group ID Delta
/// and Object ID Delta, and these values are the absolute Group ID and Object
/// ID. If the first Object in the FETCH response uses a flag that references
/// fields in the prior Object, the Subscriber MUST close the session with a
/// PROTOCOL_VIOLATION."
///
/// Each row drops one thing from flags 0x1C — the shape the corpus's first
/// objects use — and every one of them is a reference to an Object that does
/// not exist.
///
/// # Ablation
///
/// Defaulting an inherited Priority instead of refusing it —
/// `self.prior_publisher_priority.unwrap_or(128)` in place of the `ok_or` —
/// was run and gives:
///
/// ```text
/// thread 'a_first_fetch_object_may_not_reference_the_object_before_it'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:660:27:
/// flags 0x0c (no Priority) references an Object that does not exist, but it resolved to group 0 object 0
/// ```
///
/// The two missing-delta rows are guarded twice over — the Group ID rule and
/// the Object ID rule each refuse a frame with no prior Object — so no
/// single-point change to either makes them pass, and the Priority row is what
/// this ablation reaches.
#[test]
fn a_first_fetch_object_may_not_reference_the_object_before_it() {
    // Flags, then the fields those flags announce, then a payload length of 0.
    let frame = |flags: u64, fields: &[u8]| {
        let mut out = varint(flags);
        out.extend_from_slice(fields);
        out.push(0x00);
        out
    };

    // 0x1C: Group ID Delta, Object ID Delta and Priority all present,
    // subgroup mode 0b00. The one shape that states everything.
    let complete = frame(0x1C, &[0x00, 0x00, 0x80]);
    let object = FetchObjectReader::new(GroupOrder::Ascending)
        .read_object_header(&mut &complete[..])
        .expect("a first object that states everything must decode");
    assert_eq!((object.group_id, object.object_id), (0, 0));
    assert_eq!(object.subgroup_id, Some(0));
    assert_eq!(object.publisher_priority, Some(0x80));

    for (flags, fields, what) in [
        (0x14u64, &[0x00u8, 0x80][..], "no Group ID Delta"),
        (0x18, &[0x00, 0x80][..], "no Object ID Delta"),
        (0x0C, &[0x00, 0x00][..], "no Priority"),
        (0x1D, &[0x00, 0x00, 0x80][..], "the prior Object's Subgroup ID"),
        (0x1E, &[0x00, 0x00, 0x80][..], "the prior Object's Subgroup ID plus one"),
    ] {
        let bytes = frame(flags, fields);
        match FetchObjectReader::new(GroupOrder::Ascending).read_object_header(&mut &bytes[..]) {
            Ok(object) => panic!(
                "flags {flags:#04x} ({what}) references an Object that does not exist, \
                 but it resolved to group {} object {}",
                object.group_id, object.object_id
            ),
            Err(e) => assert!(
                matches!(e, CodecError::InvalidField),
                "flags {flags:#04x} ({what}) was refused as {e}, not as a malformed field"
            ),
        }
    }
}

/// A Serialization Flags value that is neither a set of flags nor an End of
/// Range marker is refused.
///
/// Draft-18 Section 11.4.4: the field "is a variable-length integer. When less
/// than 128, the bits represent flags described below", then Table 7 assigns
/// 0x8C and 0x10C, and then: "Any other value is a PROTOCOL_VIOLATION."
///
/// # Ablation
///
/// Widening the decoder's flags arm to `flags if flags <= 0xFF` was run and
/// gives:
///
/// ```text
/// thread 'a_fetch_frame_refuses_a_serialization_flags_value_the_draft_leaves_undefined'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:697:17:
/// Serialization Flags 0x80 is not a value draft-18 defines, but it decoded
/// ```
#[test]
fn a_fetch_frame_refuses_a_serialization_flags_value_the_draft_leaves_undefined() {
    for flags in [0x80u64, 0x8B, 0x8D, 0x10B, 0x10D, 0x1000, u64::MAX] {
        let mut bytes = varint(flags);
        bytes.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]);
        match FetchObjectHeader::decode(&mut &bytes[..]) {
            Ok(_) => {
                panic!("Serialization Flags {flags:#x} is not a value draft-18 defines, but it decoded")
            }
            Err(e) => assert!(
                matches!(e, CodecError::InvalidField),
                "Serialization Flags {flags:#x} was refused as {e}, not as a malformed field"
            ),
        }
    }

    // The two the draft does define, each as the first frame on a stream.
    for (flags, kind) in [(0x8Cu64, EndOfRange::NonExistent), (0x10C, EndOfRange::Unknown)] {
        let mut bytes = varint(flags);
        bytes.extend_from_slice(&[0x05, 0x0A, 0x00]);
        let object = FetchObjectReader::new(GroupOrder::Ascending)
            .read_object_header(&mut &bytes[..])
            .unwrap_or_else(|e| panic!("Serialization Flags {flags:#x} must decode: {e}"));
        assert_eq!(object.header.end_of_range(), Some(kind));
        assert_eq!((object.group_id, object.object_id), (5, 10), "the marker's own Location");
        assert_eq!(object.subgroup_id, None, "a marker names no Subgroup");
        assert_eq!(
            object.publisher_priority, None,
            "a marker states no Priority, and no Object before it has stated one either"
        );
    }
}

/// After an End of Range marker, the prior Location is the marker's but the
/// prior Subgroup ID and Priority are still the last real Object's.
///
/// Draft-18 Section 11.4.4.2 states exactly that split: "Prior Group ID and
/// prior Object ID: The values from the End of Range indicator", against "Prior
/// Subgroup ID: The Subgroup ID from the last actual Object before the End of
/// Range indicator", and the same for Priority. It then adds: "If there was no
/// prior Object, using a flag that references the prior Subgroup ID is a
/// PROTOCOL_VIOLATION."
///
/// The marker's own reported Priority is asserted here too. The draft does not
/// say what a marker reports, only what the Object after it inherits, so that
/// is a decision this crate makes — see `DEFAULT_PUBLISHER_PRIORITY` in
/// `src/data_dispatch.rs`, which is where it is written down.
///
/// # Ablation
///
/// Letting a marker overwrite the prior Subgroup ID and Priority — assigning
/// them to `None` alongside `prior_location` — was run and gives:
///
/// ```text
/// thread 'an_end_of_range_marker_moves_the_location_but_not_the_subgroup_or_priority'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:763:10:
/// the object after a marker must inherit the last real object's fields: InvalidField
/// ```
#[test]
fn an_end_of_range_marker_moves_the_location_but_not_the_subgroup_or_priority() {
    let mut reader = FetchObjectReader::new(GroupOrder::Ascending);

    // An Object with an explicit Subgroup ID of 7 and priority 0x40:
    // flags 0x1F is subgroup mode 0b11 plus both deltas and the priority.
    let mut bytes = varint(0x1F);
    bytes.extend_from_slice(&[0x02, 0x07, 0x03, 0x40, 0x00]);
    let first = reader.read_object_header(&mut &bytes[..]).expect("the first object decodes");
    assert_eq!((first.group_id, first.object_id), (2, 3));
    assert_eq!(first.subgroup_id, Some(7));

    // An End of Non-Existent Range up to group 9, object 4.
    let mut bytes = varint(0x8C);
    bytes.extend_from_slice(&[0x09, 0x04, 0x00]);
    let marker = reader.read_object_header(&mut &bytes[..]).expect("the marker decodes");
    assert_eq!((marker.group_id, marker.object_id), (9, 4));
    assert_eq!(
        marker.publisher_priority,
        Some(0x40),
        "a marker reports the Priority in force rather than one of its own"
    );

    // An Object with no deltas and no priority: every field comes from what
    // the frames before it established.
    let bytes = [0x01u8, 0x00];
    let after = reader
        .read_object_header(&mut &bytes[..])
        .expect("the object after a marker must inherit the last real object's fields");
    assert_eq!(after.group_id, 9, "the Group ID continues from the marker");
    assert_eq!(after.object_id, 5, "the Object ID continues from the marker, plus one");
    assert_eq!(after.subgroup_id, Some(7), "the Subgroup ID is the last real Object's");
    assert_eq!(after.publisher_priority, Some(0x40), "the Priority is the last real Object's");

    // A marker with no Object before it establishes no Subgroup ID, so an
    // Object that asks for one is asking for something that never existed.
    let mut reader = FetchObjectReader::new(GroupOrder::Ascending);
    let mut bytes = varint(0x8C);
    bytes.extend_from_slice(&[0x09, 0x04, 0x00]);
    reader.read_object_header(&mut &bytes[..]).expect("the marker decodes");
    let bytes = [0x11u8, 0x80, 0x00];
    match reader.read_object_header(&mut &bytes[..]) {
        Ok(object) => panic!(
            "an Object after a lone marker resolved a Subgroup ID of {:?}",
            object.subgroup_id
        ),
        Err(e) => assert!(
            matches!(e, CodecError::InvalidField),
            "the missing prior Subgroup ID was refused as {e}, not as a malformed field"
        ),
    }
}

/// A Group ID Delta walks the Group IDs in the direction the FETCH was answered
/// in, and stops at the ends of the range.
///
/// Draft-18 Section 11.4.4.1: "If the Group Order is Ascending, the Group ID is
/// the prior Object's Group ID plus the Group ID Delta + 1. If the Group Order
/// is Descending, the Group ID is the prior Object's Group ID minus the (Group
/// ID Delta + 1). If the computed Group ID would be less than 0 or greater than
/// 2^64-1, the Subscriber MUST close the Session with error
/// 'PROTOCOL_VIOLATION'."
///
/// # Ablation
///
/// Applying the ascending arithmetic under both orders — `GroupOrder::Descending
/// => prior_group.checked_add(delta)...` — was run and gives:
///
/// ```text
/// thread 'a_group_id_delta_follows_the_group_order'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:829:5:
/// assertion `left == right` failed: a descending delta of 0 moves one group down
///   left: 21
///  right: 19
/// ```
#[test]
fn a_group_id_delta_follows_the_group_order() {
    // First object: group 20, object 0, priority 128, subgroup mode 0b00.
    let first = |flags: u64| {
        let mut out = varint(flags);
        out.extend_from_slice(&[20, 0x00, 0x80, 0x00]);
        out
    };
    // A later object with a Group ID Delta of 0 and an Object ID Delta of 0.
    let step: &[u8] = &[0x0C, 0x00, 0x00, 0x00];

    let mut ascending = FetchObjectReader::new(GroupOrder::Ascending);
    ascending.read_object_header(&mut &first(0x1C)[..]).expect("the first object decodes");
    let next = ascending.read_object_header(&mut &step[..]).expect("the second object decodes");
    assert_eq!(next.group_id, 21, "an ascending delta of 0 moves one group up");

    let mut descending = FetchObjectReader::new(GroupOrder::Descending);
    descending.read_object_header(&mut &first(0x1C)[..]).expect("the first object decodes");
    let next = descending.read_object_header(&mut &step[..]).expect("the second object decodes");
    assert_eq!(next.group_id, 19, "a descending delta of 0 moves one group down");

    // Group 0 is the end of a descending range: there is no group below it.
    let mut descending = FetchObjectReader::new(GroupOrder::Descending);
    let mut bytes = varint(0x1C);
    bytes.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]);
    descending.read_object_header(&mut &bytes[..]).expect("the first object decodes");
    match descending.read_object_header(&mut &step[..]) {
        Ok(object) => {
            panic!("a descending delta below group 0 resolved to group {}", object.group_id)
        }
        Err(e) => assert!(
            matches!(e, CodecError::InvalidField),
            "the underflow was refused as {e}, not as a malformed field"
        ),
    }

    // And 2^64 - 1 is the end of an ascending one.
    let mut ascending = FetchObjectReader::new(GroupOrder::Ascending);
    let mut bytes = varint(0x1C);
    bytes.extend_from_slice(&varint(u64::MAX));
    bytes.extend_from_slice(&[0x00, 0x80, 0x00]);
    ascending.read_object_header(&mut &bytes[..]).expect("the first object decodes");
    match ascending.read_object_header(&mut &step[..]) {
        Ok(object) => {
            panic!("an ascending delta past 2^64 - 1 resolved to group {}", object.group_id)
        }
        Err(e) => assert!(
            matches!(e, CodecError::InvalidField),
            "the overflow was refused as {e}, not as a malformed field"
        ),
    }
}

/// A fetch frame the flags do not describe is refused with nothing written.
///
/// The Serialization Flags are what a reader uses to find the fields, so a
/// field the flags announce and the frame does not hold — or the reverse —
/// produces bytes that do not parse back as what was handed over. Refusing
/// before the first byte is written keeps a rejected frame out of the stream
/// entirely, rather than leaving a partial one for the next read to run into.
///
/// # Ablation
///
/// Dropping the agreement check from `FetchObjectHeader::encode` was run and
/// gives:
///
/// ```text
/// thread 'a_fetch_frame_that_disagrees_with_its_own_flags_is_not_written'
/// panicked at crates\moqtap-codec\tests\draft18_data_stream_rules.rs:914:9:
/// flags 0x1c with no Priority must be refused, got Ok(())
/// ```
#[test]
fn a_fetch_frame_that_disagrees_with_its_own_flags_is_not_written() {
    let complete = FetchObjectHeader {
        serialization_flags: 0x1C,
        group_id_delta: Some(VarInt::from_u64_moqt(0)),
        subgroup_id: None,
        object_id_delta: Some(VarInt::from_u64_moqt(0)),
        publisher_priority: Some(0x80),
        properties: Vec::new(),
        payload_length: VarInt::from_u64_moqt(0),
    };
    let mut bytes = Vec::new();
    complete.encode(&mut bytes).expect("a frame that matches its flags must encode");
    assert_eq!(
        FetchObjectHeader::decode(&mut &bytes[..]).expect("and decode back"),
        complete,
        "a fetch frame must survive its own round trip"
    );

    for (what, header) in [
        ("no Priority", FetchObjectHeader { publisher_priority: None, ..complete.clone() }),
        (
            "a Subgroup ID its mode does not announce",
            FetchObjectHeader { subgroup_id: Some(VarInt::from_u64_moqt(7)), ..complete.clone() },
        ),
        (
            "properties its flags do not announce",
            FetchObjectHeader { properties: vec![0x3C, 0x02], ..complete.clone() },
        ),
        ("no Group ID Delta", FetchObjectHeader { group_id_delta: None, ..complete.clone() }),
    ] {
        let mut bytes = Vec::new();
        let outcome = header.encode(&mut bytes);
        assert!(
            matches!(outcome, Err(CodecError::InvalidField)),
            "flags {:#04x} with {what} must be refused, got {outcome:?}",
            header.serialization_flags
        );
        assert!(bytes.is_empty(), "a refused frame with {what} still wrote {bytes:02x?}");
    }
}

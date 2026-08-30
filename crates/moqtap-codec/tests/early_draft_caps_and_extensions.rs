//! What drafts 08, 09 and 10 do *not* say about extension blocks, and the one
//! thing their encoders must still get right.
//!
//! Three rules that later drafts state were checked against drafts 07 through
//! 10 and are absent from all four. Each is recorded here as an acceptance
//! gate rather than a refusal, because the failure mode being guarded against
//! is a future change that back-ports a later draft's rule onto a draft that
//! never stated it. A codec that refuses what its draft permits is not
//! stricter, it is wrong: the frame it drops is one a conforming peer is
//! entitled to send, and the subscriber sees a session close instead of an
//! object.
//!
//! # The Reason Phrase and New Session URI caps
//!
//! Draft-11 Section 1.3.3 introduced "The reason phrase length has a maximum
//! length of 1024 bytes", and draft-11 Section 8.4 introduced "The maxmimum
//! length of the New Session URI is 8,192 bytes". Both sentences are new in
//! draft-11. Drafts 07 through 10 define the Reason Phrase only as "Provides
//! the reason for subscription error" and the New Session URI without any
//! length language at all, so neither cap binds them and neither is gated
//! here — the drafts that do state the caps are covered by their own tests.
//!
//! # A non-existent object carrying extension headers
//!
//! Draft-11 Section 9.1.1.2 opens with "Any Object may have extension headers
//! except those with Object Status 'Object Does Not Exist'. If an endpoint
//! receives a non-existent Object containing extension headers it MUST close
//! the session with a Protocol Violation." The same section in drafts 08, 09
//! and 10 opens instead with "Object Extension Headers are visible to relays
//! and allow the transmission of future metadata relevant to MOQT Object
//! distribution" and says nothing about Object Status. The sentence is an
//! addition in draft-11, so on these three drafts the combination is legal and
//! is accepted below.
//!
//! # A datagram whose extension block is zero bytes long
//!
//! Drafts 11 through 16 make a declared-but-empty extension block on a
//! datagram a session-closing offence, in three different wordings. That rule
//! needs a way to declare extensions separately from carrying them, which
//! drafts 11 and later have and drafts 08, 09 and 10 do not: their datagram
//! layouts carry the extension field unconditionally, so a length of zero is
//! the only way to say "no extensions" and contradicts nothing. Drafts 09 and
//! 10 spell the field as "Extension Headers Length (i)" outside the optional
//! brackets that later drafts put it in, and their own worked examples show
//! "Extension Headers Length = 0" as ordinary output. Draft-08 states the
//! field as an "Object Extension Count" instead, with "A value of 0 indicates
//! that no Object Extension Headers are present" — permission in as many
//! words.
//!
//! # The length that must be derived, not trusted
//!
//! The one thing these encoders must get right is the opposite of a refusal.
//! On drafts 09 and 10 the extension block is framed by a byte length, and the
//! value carries that length in a field of its own alongside the bytes. The
//! field is advisory: it records what a peer stated, which is not always
//! recoverable from the bytes, and a caller may set it to anything. So the
//! encoder must write the length the bytes actually have and never the field,
//! or it emits a frame its own decoder cannot read. Both drafts carry four
//! such sites — a subgroup object, a datagram, a status datagram and a fetch
//! object — and all eight are gated, over-stated and under-stated, because a
//! length written from the field is silent in one direction and fatal in the
//! other.

#[cfg(any(feature = "draft08", feature = "draft09", feature = "draft10"))]
use moqtap_codec::varint::VarInt;

#[cfg(any(feature = "draft08", feature = "draft09", feature = "draft10"))]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("value fits a varint")
}

/// An opaque extension block of two bytes.
///
/// Drafts 09 and 10 frame the block by byte length and do not walk into it on
/// this path, so the contents are arbitrary; only the length matters here.
#[cfg(any(feature = "draft09", feature = "draft10"))]
fn extension_bytes() -> Vec<u8> {
    vec![0xAA, 0xBB]
}

// ============================================================
// draft-08
// ============================================================

#[cfg(feature = "draft08")]
mod draft08 {
    use super::varint;
    use moqtap_codec::draft08::data_stream::{DatagramHeader, FetchObjectHeader, ObjectHeader};
    use moqtap_codec::draft08::types::ObjectStatus;

    /// One whole extension header: an even type followed by a single varint
    /// value, which is the shape draft-08 Section 8.1.1.2 defines for even
    /// types. Draft-08 counts headers rather than bytes, so the block has to
    /// tile into whole headers for the stated count to be checkable.
    fn one_extension() -> Vec<u8> {
        let mut raw = Vec::new();
        varint(0x02).encode(&mut raw);
        varint(0x2a).encode(&mut raw);
        raw
    }

    /// A subgroup object with the given status, carrying one extension header.
    fn subgroup_object(status: ObjectStatus) -> ObjectHeader {
        ObjectHeader {
            object_id: varint(1),
            extension_count: varint(1),
            extensions: one_extension(),
            payload_length: varint(0),
            object_status: status,
        }
    }

    /// A fetch object with the given status, carrying one extension header.
    fn fetch_object(status: ObjectStatus) -> FetchObjectHeader {
        FetchObjectHeader {
            group_id: varint(7),
            subgroup_id: varint(0),
            object_id: varint(1),
            publisher_priority: 128,
            extension_count: varint(1),
            extensions: one_extension(),
            object_status: status,
            payload_length: varint(0),
        }
    }

    /// Draft-08 states no rule against extensions on a non-existent object.
    ///
    /// Back-porting draft-11's sentence to the subgroup carrier fails with:
    ///
    /// ```text
    /// draft-08 states no rule against this: Err(InvalidField)
    /// ```
    #[test]
    fn a_non_existent_subgroup_object_may_carry_extensions() {
        let mut buf = Vec::new();
        let result = subgroup_object(ObjectStatus::ObjectDoesNotExist).encode_checked(&mut buf);
        assert!(result.is_ok(), "draft-08 states no rule against this: {result:?}");

        let mut cursor = &buf[..];
        let decoded = ObjectHeader::decode(&mut cursor).expect("draft-08 accepts this object");
        assert_eq!(decoded.object_status, ObjectStatus::ObjectDoesNotExist);
        assert_eq!(decoded.extensions, one_extension());
    }

    /// The fetch carrier is the one a partial back-port forgets.
    ///
    /// Back-porting draft-11's sentence to the fetch carrier fails with:
    ///
    /// ```text
    /// draft-08 states no rule against this: Err(InvalidField)
    /// ```
    #[test]
    fn a_non_existent_fetch_object_may_carry_extensions() {
        let mut buf = Vec::new();
        let result = fetch_object(ObjectStatus::ObjectDoesNotExist).encode_checked(&mut buf);
        assert!(result.is_ok(), "draft-08 states no rule against this: {result:?}");

        let mut cursor = &buf[..];
        let decoded = FetchObjectHeader::decode(&mut cursor).expect("draft-08 accepts this object");
        assert_eq!(decoded.object_status, ObjectStatus::ObjectDoesNotExist);
        assert_eq!(decoded.extensions, one_extension());
    }

    /// A datagram declaring no extensions is ordinary draft-08 output.
    ///
    /// Draft-08 Section 8.1.1 says of the Object Extension Count: "A value of 0
    /// indicates that no Object Extension Headers are present." Refusing it, as
    /// drafts 11 through 16 refuse their own zero-length block, fails with:
    ///
    /// ```text
    /// a count of zero is how draft-08 says "no extensions": Err(InvalidField)
    /// ```
    #[test]
    fn a_datagram_may_declare_no_extensions() {
        let datagram = DatagramHeader {
            track_alias: varint(2),
            group_id: varint(0),
            object_id: varint(1),
            publisher_priority: 128,
            extension_count: varint(0),
            extensions: Vec::new(),
            object_status: ObjectStatus::Normal,
            payload_length: varint(0),
        };

        let mut buf = Vec::new();
        let result = datagram.encode_checked(&mut buf);
        assert!(
            result.is_ok(),
            "a count of zero is how draft-08 says \"no extensions\": {result:?}"
        );

        let mut cursor = &buf[..];
        let decoded = DatagramHeader::decode(&mut cursor).expect("draft-08 accepts this datagram");
        assert_eq!(decoded.extension_count, varint(0));
        assert!(decoded.extensions.is_empty());
    }
}

// ============================================================
// draft-09 and draft-10
// ============================================================

/// Drafts 09 and 10 frame the extension block identically and carry the same
/// four object carriers, so the gates are written once and instantiated twice.
///
/// Spelling them out per draft is how one of the four carriers gets missed, and
/// a rule enforced at three of four entry points is the recurring shape of this
/// defect: the fetch object is unconditional where the subgroup object is
/// gated on stream type, so it is the one that reads differently and gets
/// skipped.
#[cfg(any(feature = "draft09", feature = "draft10"))]
macro_rules! byte_length_gates {
    ($module:ident, $draft:ident) => {
        mod $module {
            use super::{extension_bytes, varint};
            use moqtap_codec::$draft::data_stream::{
                DatagramHeader, DatagramStatusHeader, FetchObjectHeader, ObjectHeader,
            };
            use moqtap_codec::$draft::types::ObjectStatus;

            /// A subgroup object stating `stated` bytes of extensions while
            /// carrying [`extension_bytes`].
            fn subgroup_object(stated: u64, status: ObjectStatus) -> ObjectHeader {
                ObjectHeader {
                    object_id: varint(1),
                    extension_headers_length: varint(stated),
                    extensions: extension_bytes(),
                    payload_length: varint(0),
                    object_status: status,
                }
            }

            fn datagram(stated: u64) -> DatagramHeader {
                DatagramHeader {
                    track_alias: varint(2),
                    group_id: varint(0),
                    object_id: varint(1),
                    publisher_priority: 128,
                    extension_headers_length: varint(stated),
                    extensions: extension_bytes(),
                }
            }

            fn status_datagram(stated: u64, status: ObjectStatus) -> DatagramStatusHeader {
                DatagramStatusHeader {
                    track_alias: varint(2),
                    group_id: varint(0),
                    object_id: varint(1),
                    publisher_priority: 128,
                    extension_headers_length: varint(stated),
                    extensions: extension_bytes(),
                    object_status: status,
                }
            }

            fn fetch_object(stated: u64, status: ObjectStatus) -> FetchObjectHeader {
                FetchObjectHeader {
                    group_id: varint(7),
                    subgroup_id: varint(0),
                    object_id: varint(1),
                    publisher_priority: 128,
                    extension_headers_length: varint(stated),
                    extensions: extension_bytes(),
                    object_status: status,
                    payload_length: varint(0),
                }
            }

            /// The subgroup object writes the length its bytes hold.
            ///
            /// Writing the field instead fails on the over-stated case with:
            ///
            /// ```text
            /// an over-stated length must not reach the wire: UnexpectedEnd
            /// ```
            ///
            /// and on the under-stated case with:
            ///
            /// ```text
            /// assertion `left == right` failed: an under-stated length must not reach the wire
            ///   left: []
            ///  right: [170, 187]
            /// ```
            #[test]
            fn a_subgroup_object_writes_the_length_its_bytes_hold() {
                for stated in [99, 0] {
                    let mut buf = Vec::new();
                    subgroup_object(stated, ObjectStatus::Normal).encode(&mut buf);

                    let mut cursor = &buf[..];
                    let decoded = ObjectHeader::decode(&mut cursor)
                        .expect("an over-stated length must not reach the wire");
                    assert_eq!(
                        decoded.extensions,
                        extension_bytes(),
                        "an under-stated length must not reach the wire"
                    );
                    assert_eq!(decoded.extension_headers_length, varint(2));
                    assert!(cursor.is_empty(), "the frame must end where the decoder thinks");
                }
            }

            /// The datagram writes the length its bytes hold.
            ///
            /// Writing the field instead fails on the over-stated case with:
            ///
            /// ```text
            /// an over-stated length must not reach the wire: UnexpectedEnd
            /// ```
            ///
            /// and on the under-stated case with:
            ///
            /// ```text
            /// assertion `left == right` failed: an under-stated length must not reach the wire
            ///   left: []
            ///  right: [170, 187]
            /// ```
            #[test]
            fn a_datagram_writes_the_length_its_bytes_hold() {
                for stated in [99, 0] {
                    let mut buf = Vec::new();
                    datagram(stated).encode(&mut buf);

                    let mut cursor = &buf[..];
                    let decoded = DatagramHeader::decode(&mut cursor)
                        .expect("an over-stated length must not reach the wire");
                    assert_eq!(
                        decoded.extensions,
                        extension_bytes(),
                        "an under-stated length must not reach the wire"
                    );
                    assert_eq!(decoded.extension_headers_length, varint(2));
                    assert!(cursor.is_empty(), "the frame must end where the decoder thinks");
                }
            }

            /// The status datagram writes the length its bytes hold.
            ///
            /// Writing the field instead fails on the over-stated case with:
            ///
            /// ```text
            /// an over-stated length must not reach the wire: UnexpectedEnd
            /// ```
            ///
            /// and on the under-stated case with:
            ///
            /// ```text
            /// an over-stated length must not reach the wire: VarInt(UnexpectedEnd)
            /// ```
            ///
            /// The under-stated case fails at a different point here, and on a
            /// different error: the two extension bytes left unread are taken
            /// for the Object Status varint, 0xAA opens a two-byte varint, and
            /// the byte it needs is the last one in the frame.
            #[test]
            fn a_status_datagram_writes_the_length_its_bytes_hold() {
                for stated in [99, 0] {
                    let mut buf = Vec::new();
                    status_datagram(stated, ObjectStatus::ObjectDoesNotExist).encode(&mut buf);

                    let mut cursor = &buf[..];
                    let decoded = DatagramStatusHeader::decode(&mut cursor)
                        .expect("an over-stated length must not reach the wire");
                    assert_eq!(
                        decoded.extensions,
                        extension_bytes(),
                        "an under-stated length must not reach the wire"
                    );
                    assert_eq!(decoded.extension_headers_length, varint(2));
                    assert_eq!(decoded.object_status, ObjectStatus::ObjectDoesNotExist);
                    assert!(cursor.is_empty(), "the frame must end where the decoder thinks");
                }
            }

            /// The fetch object writes the length its bytes hold.
            ///
            /// This is the carrier a partial fix leaves behind. Writing the
            /// field instead fails on the over-stated case with:
            ///
            /// ```text
            /// an over-stated length must not reach the wire: UnexpectedEnd
            /// ```
            ///
            /// and on the under-stated case with:
            ///
            /// ```text
            /// assertion `left == right` failed: an under-stated length must not reach the wire
            ///   left: []
            ///  right: [170, 187]
            /// ```
            #[test]
            fn a_fetch_object_writes_the_length_its_bytes_hold() {
                for stated in [99, 0] {
                    let mut buf = Vec::new();
                    fetch_object(stated, ObjectStatus::Normal).encode(&mut buf);

                    let mut cursor = &buf[..];
                    let decoded = FetchObjectHeader::decode(&mut cursor)
                        .expect("an over-stated length must not reach the wire");
                    assert_eq!(
                        decoded.extensions,
                        extension_bytes(),
                        "an under-stated length must not reach the wire"
                    );
                    assert_eq!(decoded.extension_headers_length, varint(2));
                    assert!(cursor.is_empty(), "the frame must end where the decoder thinks");
                }
            }

            /// This draft states no rule against extensions on a non-existent
            /// object, on any of the three carriers that can announce a status.
            ///
            /// Back-porting draft-11's sentence fails with:
            ///
            /// ```text
            /// this draft states no rule against this: Err(InvalidField)
            /// ```
            #[test]
            fn a_non_existent_object_may_carry_extensions_on_every_carrier() {
                let mut buf = Vec::new();
                let result =
                    subgroup_object(2, ObjectStatus::ObjectDoesNotExist).encode_checked(&mut buf);
                assert!(result.is_ok(), "this draft states no rule against this: {result:?}");
                let mut cursor = &buf[..];
                let decoded = ObjectHeader::decode(&mut cursor).expect("this draft accepts it");
                assert_eq!(decoded.object_status, ObjectStatus::ObjectDoesNotExist);
                assert_eq!(decoded.extensions, extension_bytes());

                let mut buf = Vec::new();
                let result =
                    fetch_object(2, ObjectStatus::ObjectDoesNotExist).encode_checked(&mut buf);
                assert!(result.is_ok(), "this draft states no rule against this: {result:?}");
                let mut cursor = &buf[..];
                let decoded =
                    FetchObjectHeader::decode(&mut cursor).expect("this draft accepts it");
                assert_eq!(decoded.object_status, ObjectStatus::ObjectDoesNotExist);
                assert_eq!(decoded.extensions, extension_bytes());

                let mut buf = Vec::new();
                let result =
                    status_datagram(2, ObjectStatus::ObjectDoesNotExist).encode_checked(&mut buf);
                assert!(result.is_ok(), "this draft states no rule against this: {result:?}");
                let mut cursor = &buf[..];
                let decoded =
                    DatagramStatusHeader::decode(&mut cursor).expect("this draft accepts it");
                assert_eq!(decoded.object_status, ObjectStatus::ObjectDoesNotExist);
                assert_eq!(decoded.extensions, extension_bytes());
            }

            /// A datagram whose extension block is zero bytes long is ordinary
            /// output on this draft, on both datagram carriers.
            ///
            /// The field is not optional here, so zero is the only way to say
            /// "no extensions". Back-porting draft-14's refusal fails with:
            ///
            /// ```text
            /// a zero-length block is how this draft says "no extensions": Err(InvalidField)
            /// ```
            #[test]
            fn a_datagram_may_carry_a_zero_length_extension_block() {
                let empty = DatagramHeader { extensions: Vec::new(), ..datagram(0) };
                let mut buf = Vec::new();
                let result = empty.encode_checked(&mut buf);
                assert!(
                    result.is_ok(),
                    "a zero-length block is how this draft says \"no extensions\": {result:?}"
                );
                let mut cursor = &buf[..];
                let decoded = DatagramHeader::decode(&mut cursor).expect("this draft accepts it");
                assert_eq!(decoded.extension_headers_length, varint(0));
                assert!(decoded.extensions.is_empty());

                let empty = DatagramStatusHeader {
                    extensions: Vec::new(),
                    ..status_datagram(0, ObjectStatus::Normal)
                };
                let mut buf = Vec::new();
                let result = empty.encode_checked(&mut buf);
                assert!(
                    result.is_ok(),
                    "a zero-length block is how this draft says \"no extensions\": {result:?}"
                );
                let mut cursor = &buf[..];
                let decoded =
                    DatagramStatusHeader::decode(&mut cursor).expect("this draft accepts it");
                assert_eq!(decoded.extension_headers_length, varint(0));
                assert!(decoded.extensions.is_empty());
            }

            /// A subgroup object may also carry a zero-length block, and that
            /// is the reason the datagram rule cannot simply be applied to
            /// every carrier on the drafts that do state it.
            ///
            /// This draft's own worked example shows it: "{ Object ID = 1
            /// Extension Headers Length = 0 Object Payload Length = 4 Payload =
            /// "efgh" }".
            #[test]
            fn a_subgroup_object_may_carry_a_zero_length_extension_block() {
                let empty = ObjectHeader {
                    extensions: Vec::new(),
                    ..subgroup_object(0, ObjectStatus::Normal)
                };
                let mut buf = Vec::new();
                let result = empty.encode_checked(&mut buf);
                assert!(
                    result.is_ok(),
                    "a zero-length block is how this draft says \"no extensions\": {result:?}"
                );
                let mut cursor = &buf[..];
                let decoded = ObjectHeader::decode(&mut cursor).expect("this draft accepts it");
                assert_eq!(decoded.extension_headers_length, varint(0));
                assert!(decoded.extensions.is_empty());
            }
        }
    };
}

#[cfg(feature = "draft09")]
byte_length_gates!(draft09, draft09);

#[cfg(feature = "draft10")]
byte_length_gates!(draft10, draft10);

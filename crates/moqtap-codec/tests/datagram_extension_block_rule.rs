//! A datagram that announces extensions must carry some.
//!
//! Drafts 11 through 16 all state it, in three different wordings for the same
//! rule. Drafts 11, 12 and 13 name the types: "If an endpoint receives a
//! datagram with Type 0x01 and Extension Headers Length is 0, it MUST close the
//! session with Protocol Violation", and again for Type 0x03. Drafts 14 and 15
//! say it of the field: "If an endpoint receives a datagram with Extensions
//! Present as 'Yes' and a Extension Headers Length of 0". Draft-16 says it of
//! the bit: "with the EXTENSIONS bit set and an Extension Headers Length of 0".
//!
//! Drafts 07 through 10 state no such rule, and drafts 17, 18 and 19 drop the
//! sentence, so neither end of the series is gated here. The reason at the
//! early end is not that the field is missing - draft-09 and draft-10 datagrams
//! do carry an Extension Headers Length - it is that those drafts have no way
//! to announce extensions separately from carrying them, so a length of 0 says
//! only that there are none and contradicts nothing.
//!
//! # Why this is a datagram rule and only a datagram rule
//!
//! The same drafts require the opposite encoding on a subgroup stream: "Objects
//! with no extensions set Extension Headers Length to 0." The type byte there
//! is fixed for the whole stream, so an object with nothing to declare has no
//! other way to say so. A single check applied to both carriers breaks one of
//! them, which is why each gate below drives the datagram reader directly and
//! why the fetch and subgroup readers are deliberately untouched.
//!
//! Only draft-14 enforced this. Finding it needed the drafts to be read three
//! times over, because a search for any one of the three wordings finds only
//! the drafts that use it — searching for draft-14's phrasing reports that
//! drafts 11, 12 and 13 state no such rule, and they do.
//!
//! # Draft-14 is driven by a gate of its own
//!
//! Its datagram reader is a third shape. Drafts 11 to 13 take the presence of
//! extensions as an argument and stop at the header; drafts 15 and 16 read a
//! type byte and stop at the header; draft-14 reads a type byte into a
//! `DatagramType` whose accessors answer the question, and then reads the whole
//! datagram. Neither macro reaches it, so it has a gate written out rather than
//! a row in a list.
//!
//! The bytes are not a third shape. Behind the type byte draft-14 reads the
//! same fields in the same order as the two groups around it, which is why the
//! body builder below is shared by all six drafts and only the entry point
//! differs.

#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
use moqtap_codec::error::CodecError;
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
use moqtap_codec::varint::VarInt;

#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
fn vi(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("value fits a varint")
}

/// A datagram body for drafts 11 to 13: alias, group, object, priority, then an
/// extension block of the given length.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
fn datagram_body(extension_bytes: usize) -> Vec<u8> {
    let mut wire = Vec::new();
    vi(1).encode(&mut wire);
    vi(2).encode(&mut wire);
    vi(3).encode(&mut wire);
    wire.push(128);
    VarInt::from_usize(extension_bytes).encode(&mut wire);
    wire.extend(std::iter::repeat_n(0xAA, extension_bytes));
    wire
}

/// The same shape for drafts 14, 15 and 16, behind the type byte those drafts
/// read for themselves. Type `0x01` says extensions present, Object ID present,
/// priority present on all three.
#[cfg(any(feature = "draft14", feature = "draft15", feature = "draft16"))]
fn typed_datagram(extension_bytes: usize) -> Vec<u8> {
    let mut wire = vec![0x01];
    wire.extend_from_slice(&datagram_body(extension_bytes));
    wire
}

/// Drafts 11 to 13 expose the reader as `decode_with_extensions`.
///
/// # What this catches, observed by removing each check and running it
///
/// Every draft returned a header claiming an extension block it did not have:
///
/// ```text
/// a datagram announcing extensions cannot declare a length of 0, got Ok(DatagramHeader { track_alias: VarInt(1), group_id: VarInt(2), object_id: VarInt(3), publisher_priority: 128, extension_headers_length: VarInt(0), extensions: [], end_of_group: false })
/// ```
macro_rules! early_datagram_gate {
    ($fname:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $fname() {
            use moqtap_codec::$draft::data_stream::DatagramHeader;

            let wire = datagram_body(0);
            let got = DatagramHeader::decode_with_extensions(true, &mut &wire[..]);
            assert!(
                matches!(got, Err(CodecError::InvalidField)),
                "a datagram announcing extensions cannot declare a length of 0, got {got:?}"
            );

            // A non-empty block is lawful, so the gate observes the zero and
            // not the presence of the field.
            let wire = datagram_body(2);
            DatagramHeader::decode_with_extensions(true, &mut &wire[..])
                .expect("a datagram with a real extension block is lawful");
        }
    };
}

/// Drafts 15 and 16 read the type byte themselves.
macro_rules! typed_datagram_gate {
    ($fname:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $fname() {
            use moqtap_codec::$draft::data_stream::DatagramHeader;

            let wire = typed_datagram(0);
            let got = DatagramHeader::decode(&mut &wire[..]);
            assert!(
                matches!(got, Err(CodecError::InvalidField)),
                "a datagram announcing extensions cannot declare a length of 0, got {got:?}"
            );

            let wire = typed_datagram(2);
            DatagramHeader::decode(&mut &wire[..])
                .expect("a datagram with a real extension block is lawful");
        }
    };
}

early_datagram_gate!(draft11_datagram_extensions_are_not_empty, "draft11", draft11);
early_datagram_gate!(draft12_datagram_extensions_are_not_empty, "draft12", draft12);
early_datagram_gate!(draft13_datagram_extensions_are_not_empty, "draft13", draft13);
/// Draft-14 reads the type byte for itself, like drafts 15 and 16, and then
/// reads past the header to the end of the datagram. So this drives
/// `DatagramObject` rather than a header decoder, on the bytes the two drafts
/// after it are driven on.
///
/// # What this catches, observed by removing the check and running it
///
/// ```text
/// a datagram announcing extensions cannot declare a length of 0, got Ok(DatagramObject { datagram_type: DatagramType(1), track_alias: VarInt(1), group_id: VarInt(2), object_id: VarInt(3), publisher_priority: 128, extension_headers: [], status: None, payload: [] })
/// ```
#[cfg(feature = "draft14")]
#[test]
fn draft14_datagram_extensions_are_not_empty() {
    use moqtap_codec::draft14::data_stream::DatagramObject;

    let wire = typed_datagram(0);
    let got = DatagramObject::decode(&mut &wire[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidField)),
        "a datagram announcing extensions cannot declare a length of 0, got {got:?}"
    );

    // A non-empty block is lawful, so the gate observes the zero and not the
    // presence of the field.
    let wire = typed_datagram(2);
    DatagramObject::decode(&mut &wire[..])
        .expect("a datagram with a real extension block is lawful");
}

typed_datagram_gate!(draft15_datagram_extensions_are_not_empty, "draft15", draft15);
typed_datagram_gate!(draft16_datagram_extensions_are_not_empty, "draft16", draft16);

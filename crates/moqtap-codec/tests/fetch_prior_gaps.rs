//! The Prior gap conditions one fetch stream shows, through each draft's
//! `FetchGaps`, each draft's `FetchObjectReader` from draft-15, and
//! `AnyFetchObjectReader::read_object`.
//!
//! Drafts 11-13 state draft-11 Section 10.1's two conditions and "an Object
//! with a Group ID within a previously communicated gap", with Prior Group ID
//! Gap (Type 0x40) free to repeat. Drafts 14-23 add Prior Object ID Gap, limit
//! each Object to one instance, and add the conditions on a gap covering an
//! Object received earlier (draft-14 Section 11.1, draft-23 Section 10.8).
//! The covering conditions are not refused on 16-22, nor the within-gap ones
//! on 18-22, where draft-16 Section 2.1 and draft-18 Section 2.1 contradict
//! them.

use moqtap_codec::error::CodecError;

#[allow(dead_code)]
fn refused<T>(r: Result<T, CodecError>) -> bool {
    matches!(r, Err(CodecError::MalformedTrack { .. }))
}

/// A property block of even Types, in ascending Type order, written with
/// absolute or delta Types. Every Type and value here fits one byte on every
/// draft's varint, except Type 0x40, which RFC 9000 writes in two.
#[allow(dead_code)]
fn block(entries: &[(u64, u64)], delta: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev = 0;
    for &(ty, value) in entries {
        let wire = if delta { ty - prev } else { ty };
        prev = ty;
        if wire >= 0x40 {
            out.extend_from_slice(&[0x40 | (wire >> 8) as u8, wire as u8]);
        } else {
            out.push(wire as u8);
        }
        out.push(value as u8);
    }
    out
}

macro_rules! early {
    ($draft:ident, $feature:literal) => {
        #[cfg(feature = $feature)]
        mod $draft {
            use super::*;
            use moqtap_codec::$draft::data_stream::FetchGaps;

            fn gaps(values: &[u64]) -> Vec<u8> {
                block(&values.iter().map(|&v| (0x40, v)).collect::<Vec<_>>(), false)
            }

            #[test]
            fn a_gap_larger_than_the_group_id_is_refused() {
                assert!(refused(FetchGaps::new().check(5, 0, &gaps(&[7, 6]))));
                FetchGaps::new().check(5, 0, &gaps(&[2, 6])).unwrap();
            }

            #[test]
            fn objects_of_one_group_need_a_value_in_common() {
                let mut g = FetchGaps::new();
                g.check(5, 0, &gaps(&[2, 3])).unwrap();
                g.check(5, 1, &gaps(&[3])).unwrap();
                assert!(refused(g.check(5, 2, &gaps(&[2]))));
                let mut g = FetchGaps::new();
                g.check(5, 0, &gaps(&[2])).unwrap();
                g.check(6, 0, &gaps(&[3])).unwrap();
            }

            #[test]
            fn a_group_within_the_gap_before_it_is_refused() {
                let mut g = FetchGaps::new();
                g.check(10, 0, &gaps(&[2])).unwrap();
                assert!(refused(g.check(8, 0, &[])));
                let mut g = FetchGaps::new();
                g.check(10, 0, &gaps(&[2])).unwrap();
                g.check(7, 0, &[]).unwrap();
            }

            #[test]
            fn a_gap_covering_the_group_before_is_not_a_condition_here() {
                let mut g = FetchGaps::new();
                g.check(9, 0, &[]).unwrap();
                g.check(10, 0, &gaps(&[2])).unwrap();
            }
        }
    };
}

macro_rules! late {
    ($draft:ident, $feature:literal, $delta:expr, $covering:expr, $within:expr) => {
        #[cfg(feature = $feature)]
        mod $draft {
            use super::*;
            use moqtap_codec::$draft::data_stream::FetchGaps;

            fn props(entries: &[(u64, u64)]) -> Vec<u8> {
                block(entries, $delta)
            }

            #[test]
            fn the_conditions_one_object_shows_are_refused() {
                assert!(refused(FetchGaps::new().check(1, 0, &props(&[(0x3C, 2)]))));
                assert!(refused(FetchGaps::new().check(5, 0, &props(&[(0x3E, 1)]))));
                assert!(refused(FetchGaps::new().check(5, 5, &props(&[(0x3C, 1), (0x3C, 1)]))));
            }

            #[test]
            fn objects_of_one_group_with_different_values_are_refused() {
                let mut g = FetchGaps::new();
                g.check(5, 0, &props(&[(0x3C, 2)])).unwrap();
                g.check(5, 1, &props(&[(0x3C, 2)])).unwrap();
                assert!(refused(g.check(5, 2, &props(&[(0x3C, 3)]))));
                let mut g = FetchGaps::new();
                g.check(5, 0, &props(&[(0x3C, 2)])).unwrap();
                g.check(9, 0, &props(&[(0x3C, 3)])).unwrap();
            }

            #[test]
            fn a_group_gap_covering_the_group_before_is_refused() {
                let mut g = FetchGaps::new();
                g.check(9, 0, &[]).unwrap();
                assert_eq!(refused(g.check(10, 0, &props(&[(0x3C, 2)]))), $covering);
                let mut g = FetchGaps::new();
                g.check(7, 0, &[]).unwrap();
                g.check(10, 0, &props(&[(0x3C, 2)])).unwrap();
            }

            #[test]
            fn a_group_within_the_gap_before_it_is_refused() {
                let mut g = FetchGaps::new();
                g.check(10, 0, &props(&[(0x3C, 2)])).unwrap();
                assert_eq!(refused(g.check(9, 0, &[])), $within);
            }

            #[test]
            fn an_object_gap_covering_the_object_before_is_refused() {
                let mut g = FetchGaps::new();
                g.check(3, 8, &[]).unwrap();
                assert_eq!(refused(g.check(3, 10, &props(&[(0x3E, 2)]))), $covering);
                let mut g = FetchGaps::new();
                g.check(3, 7, &[]).unwrap();
                g.check(3, 10, &props(&[(0x3E, 2)])).unwrap();
            }

            #[test]
            fn a_block_that_does_not_parse_is_refused() {
                assert!(matches!(
                    FetchGaps::new().check(3, 0, &[0x3C]),
                    Err(CodecError::MalformedObjectProperties { .. })
                ));
            }
        }
    };
}

early!(draft11, "draft11");
early!(draft12, "draft12");
early!(draft13, "draft13");
late!(draft14, "draft14", false, true, true);
late!(draft15, "draft15", false, true, true);
late!(draft16, "draft16", true, false, true);
late!(draft17, "draft17", true, false, true);
late!(draft18, "draft18", true, false, false);
late!(draft19, "draft19", true, false, false);
late!(draft20, "draft20", true, false, false);
late!(draft21, "draft21", true, false, false);
late!(draft22, "draft22", true, false, false);
late!(draft23, "draft23", true, true, true);

/// The facade reader applies the same conditions, and only `read_object`
/// does: draft-14 fetch objects, Group 5, Prior Group ID Gap 2 then 3.
#[cfg(feature = "draft14")]
#[test]
fn the_facade_reader_refuses_what_the_stream_shows() {
    use moqtap_codec::data_dispatch::{AnyFetchGroupOrder, AnyFetchObjectReader};
    use moqtap_codec::dispatch::AnyFetchHeader;
    use moqtap_codec::version::DraftVersion;

    let bytes =
        hex::decode("0502 0500008002 3c02 01aa 0500018002 3c03 01bb".replace(' ', "")).unwrap();
    let mut cursor = &bytes[..];
    let header = AnyFetchHeader::decode_stream(DraftVersion::Draft14, &mut cursor).unwrap();
    let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending).unwrap();
    let mut meta = reader.clone();
    let mut meta_cursor = cursor;
    reader.read_object(&mut cursor).unwrap();
    assert!(refused(reader.read_object(&mut cursor)));
    meta.read_object_meta(&mut meta_cursor).unwrap();
    meta.read_object_meta(&mut meta_cursor).unwrap();
}

/// Objects 0 and 1 of Group 5 with Prior Group ID Gap 2 then 3, the second
/// taking its Group ID, Object ID and Priority from the first. The bytes are
/// the same on drafts 15-23.
#[allow(dead_code)]
const DIFFERENT_VALUES: &str = "3c05008002 3c02 01aa 2002 3c03 01bb";

#[allow(unused_macros)]
macro_rules! reader {
    ($draft:ident, $feature:literal, $new:expr) => {
        #[cfg(feature = $feature)]
        #[test]
        fn $draft() {
            use bytes::Buf;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::data_stream::*;

            let bytes = hex::decode(DIFFERENT_VALUES.replace(' ', "")).unwrap();
            let mut cursor = &bytes[..];
            let mut reader = $new;
            let first = reader.read_object_header(&mut cursor).unwrap();
            cursor.advance(first.payload_length().into_inner() as usize);
            assert!(refused(reader.read_object_header(&mut cursor)));
        }
    };
}

mod the_draft_reader_refuses_what_the_stream_shows {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(any(
        feature = "draft15",
        feature = "draft17",
        feature = "draft18",
        feature = "draft19",
        feature = "draft20",
        feature = "draft21",
        feature = "draft22",
        feature = "draft23"
    ))]
    trait PayloadLength {
        fn payload_length(&self) -> moqtap_codec::varint::VarInt;
    }
    #[cfg(feature = "draft15")]
    impl PayloadLength for moqtap_codec::draft15::data_stream::FetchObjectHeader {
        fn payload_length(&self) -> moqtap_codec::varint::VarInt {
            self.payload_length
        }
    }
    macro_rules! resolved {
        ($($draft:ident @ $feature:literal),+) => {$(
            #[cfg(feature = $feature)]
            impl PayloadLength for moqtap_codec::$draft::data_stream::FetchObject {
                fn payload_length(&self) -> moqtap_codec::varint::VarInt {
                    self.header.payload_length
                }
            }
        )+};
    }
    resolved!(
        draft17 @ "draft17", draft18 @ "draft18", draft19 @ "draft19", draft20 @ "draft20",
        draft21 @ "draft21", draft22 @ "draft22", draft23 @ "draft23"
    );

    reader!(draft15, "draft15", FetchObjectReader::new());
    reader!(draft17, "draft17", FetchObjectReader::new());
    reader!(draft18, "draft18", FetchObjectReader::new(GroupOrder::Ascending));
    reader!(draft19, "draft19", FetchObjectReader::new(GroupOrder::Ascending));
    reader!(draft20, "draft20", FetchObjectReader::new(GroupOrder::Ascending));
    reader!(draft21, "draft21", FetchObjectReader::new(GroupOrder::Ascending));
    reader!(draft22, "draft22", FetchObjectReader::new(GroupOrder::Ascending));
    reader!(draft23, "draft23", FetchObjectReader::new(GroupOrder::Ascending));

    /// Draft-16's stream does not resolve Locations, so `resolve` applies them.
    #[cfg(feature = "draft16")]
    #[test]
    fn draft16() {
        use bytes::Buf;
        use moqtap_codec::draft16::data_stream::{FetchObjectHeader, FetchObjectReader};

        let bytes = hex::decode(DIFFERENT_VALUES.replace(' ', "")).unwrap();
        let mut cursor = &bytes[..];
        let mut reader = FetchObjectReader::new();
        let first = FetchObjectHeader::decode(&mut cursor).unwrap();
        reader.resolve(&first).unwrap();
        cursor.advance(first.payload_length.into_inner() as usize);
        let second = FetchObjectHeader::decode(&mut cursor).unwrap();
        assert!(refused(reader.resolve(&second)));
    }
}

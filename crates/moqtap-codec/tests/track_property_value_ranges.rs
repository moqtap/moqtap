//! Value ranges in the second registry — extension headers, then properties.
//!
//! Drafts 15 and earlier state every value range they have about a message
//! field or a Message Parameter. Draft-16 opens a second registry: Extension
//! Headers, some of which are Track Extensions and ride at the tail of
//! SUBSCRIBE_OK, PUBLISH and FETCH_OK. Draft-17 renames the registry to
//! Properties and keeps the shape. Two of its entries state a range and a
//! consequence, and the consequence is a session close:
//!
//! > The DEFAULT_PUBLISHER_GROUP_ORDER extension (Extension Header Type 0x22) is
//! > a Track Extension. [...] The allowed values are Ascending (0x1) or
//! > Descending (0x2). If an endpoint receives a value outside this range, it
//! > MUST close the session with PROTOCOL_VIOLATION.
//!
//! > The DYNAMIC_GROUPS Extension (Extension Header Type 0x30) is a Track
//! > Extension. The allowed values are 0 or 1. [...] If an endpoint receives a
//! > value larger than 1, it MUST close the session with PROTOCOL_VIOLATION.
//!
//! # Two registries, one set of numbers
//!
//! Type 0x22 is GROUP_ORDER in the Message Parameter registry and
//! DEFAULT_PUBLISHER_GROUP_ORDER here, and the two admit the same pair of values
//! while meaning different things — one subscriber's preference against a
//! property of the track. Type 0x30 is DYNAMIC_GROUPS here and is a Message
//! Parameter on draft-15 alone, which is where `parameter_value_ranges.rs`
//! drives it. The numbers agreeing on these two entries is a coincidence of the
//! registries and not a shared table, so the two are checked apart and reported
//! apart: `TrackPropertyValueOutOfRange` rather than
//! `ParameterValueOutOfRange`.
//!
//! # Hiding a value one level down
//!
//! Immutable Extensions — Immutable Properties from draft-17 — is Type 0xB, and
//! its value is a sequence of Key-Value-Pairs that are themselves extensions or
//! properties. Drafts 17, 18 and 19 say what that means for anything reading
//! them: "When looking for the value of a property, processors MUST search both
//! the mutable properties and the contents of Immutable Properties."
//!
//! So a check applied to the outer run alone is one a peer opts out of by
//! moving a single pair inside the block, and the block is not a corner of the
//! protocol — it is where an Original Publisher puts what relays must not
//! rewrite, which is where a track's group order belongs. Every refusal below is
//! driven twice, once beside the block and once inside it.
//!
//! # What is deliberately carried
//!
//! DEFAULT_PUBLISHER_PRIORITY (0x0E) says "Priorities above 255 are invalid" and
//! names no consequence, two subsections away from two entries that each name
//! one in the next clause. A table assembled from "which entries mention a
//! range" rather than "which entries state a consequence" closes sessions over
//! it, and `a_priority_the_draft_calls_invalid_without_saying_more_is_carried`
//! is what fails when one does.

#![cfg(any(
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]

/// DEFAULT_PUBLISHER_GROUP_ORDER.
const DEFAULT_PUBLISHER_GROUP_ORDER: u64 = 0x22;
/// DYNAMIC_GROUPS.
const DYNAMIC_GROUPS: u64 = 0x30;
/// DEFAULT_PUBLISHER_PRIORITY, which states a range and no consequence.
const DEFAULT_PUBLISHER_PRIORITY: u64 = 0x0E;
/// Immutable Extensions on draft-16, Immutable Properties from draft-17.
const IMMUTABLE: u64 = 0x0B;

/// The values the two ranges refuse, and the value each entry is refused at.
const OUT_OF_RANGE: &[(u64, u64)] = &[
    (DEFAULT_PUBLISHER_GROUP_ORDER, 0),
    (DEFAULT_PUBLISHER_GROUP_ORDER, 3),
    (DEFAULT_PUBLISHER_GROUP_ORDER, 300),
    (DYNAMIC_GROUPS, 2),
    (DYNAMIC_GROUPS, 9),
];

/// The values the two ranges admit, which a table that over-reached would break.
const IN_RANGE: &[(u64, u64)] = &[
    (DEFAULT_PUBLISHER_GROUP_ORDER, 1),
    (DEFAULT_PUBLISHER_GROUP_ORDER, 2),
    (DYNAMIC_GROUPS, 0),
    (DYNAMIC_GROUPS, 1),
];

/// Build the four modules, which differ only in the varint profile their draft
/// writes and in whether SUBSCRIBE_OK still carries a Request ID.
///
/// The frames are hand-built rather than produced by this codec's encoder,
/// because the encoder now refuses the values under test — which is the point of
/// `a_value_the_decoder_refuses_is_never_written` below, and would leave the
/// decode side with no fixture if the two shared one. Everything except the run
/// of extensions is a fixed prelude: the message type, the sixteen-bit payload
/// length, an empty Parameters list, and on draft-16 a Request ID.
macro_rules! track_property_range_gate {
    (
        $module:ident,
        $feature:literal,
        $draft:ident,
        $field:ident,
        put_varint = $put_varint:item,
        prelude = $prelude:expr,
        shell = $shell:expr,
        also_refused = $also_refused:expr
    ) => {
        #[cfg(feature = $feature)]
        mod $module {
            use super::{DEFAULT_PUBLISHER_PRIORITY, IMMUTABLE, IN_RANGE, OUT_OF_RANGE};
            use moqtap_codec::$draft::message::*;
            use moqtap_codec::error::CodecError;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::varint::{Moqt17, Moqt18, MoqtProfile, VarInt};

            $put_varint

            /// One Key-Value-Pair with a bare varint value, its Type written as
            /// a delta from `prev`.
            fn kvp_varint(prev: &mut u64, key: u64, value: u64, out: &mut Vec<u8>) {
                put_varint(key - *prev, out);
                *prev = key;
                put_varint(value, out);
            }

            /// One Key-Value-Pair with a length-prefixed value.
            fn kvp_bytes(prev: &mut u64, key: u64, value: &[u8], out: &mut Vec<u8>) {
                put_varint(key - *prev, out);
                *prev = key;
                put_varint(value.len() as u64, out);
                out.extend_from_slice(value);
            }

            /// A run holding one varint-valued entry, starting the delta at 0.
            fn beside(key: u64, value: u64) -> Vec<u8> {
                let mut out = Vec::new();
                kvp_varint(&mut 0, key, value, &mut out);
                out
            }

            /// The same entry, moved inside the Immutable block.
            fn inside(key: u64, value: u64) -> Vec<u8> {
                let mut nested = Vec::new();
                kvp_varint(&mut 0, key, value, &mut nested);
                let mut out = Vec::new();
                kvp_bytes(&mut 0, IMMUTABLE, &nested, &mut out);
                out
            }

            /// A SUBSCRIBE_OK whose tail is `run`.
            fn subscribe_ok(run: &[u8]) -> Vec<u8> {
                let mut payload: Vec<u8> = Vec::new();
                $prelude(&mut payload);
                payload.extend_from_slice(run);

                let mut wire = Vec::new();
                put_varint(0x04, &mut wire);
                wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                wire.extend_from_slice(&payload);
                wire
            }

            /// The tail of a decoded SUBSCRIBE_OK.
            fn tail_of(wire: &[u8]) -> Result<Vec<KeyValuePair>, CodecError> {
                match ControlMessage::decode(&mut &wire[..])? {
                    ControlMessage::SubscribeOk(m) => Ok(m.$field),
                    other => panic!("the fixture is a SUBSCRIBE_OK: {other:?}"),
                }
            }

            /// Each entry the draft gives a range, refused outside it, whether it
            /// arrives beside the Immutable block or inside it.
            ///
            /// # What it catches
            ///
            /// Both messages below were measured on draft-16 and again on
            /// draft-19, and are identical: the two registries differ in name
            /// and in which varint spells them, not in what a violation looks
            /// like once decoded.
            ///
            /// With the value check removed from the decode path, the value is
            /// handed to the caller as an ordinary entry:
            ///
            /// ```text
            /// assertion `left == right` failed: type 0x22 value 0 beside the immutable block must be refused
            ///   left: Ok([KeyValuePair { key: VarInt(34), value: Varint(VarInt(0)) }])
            ///  right: Err(TrackPropertyValueOutOfRange { key: 34, value: 0 })
            /// ```
            ///
            /// With the check present but not descending into the block, the
            /// outer half passes and the nested half reports the block itself:
            ///
            /// ```text
            /// assertion `left == right` failed: type 0x22 value 0 inside the immutable block must be refused
            ///   left: Ok([KeyValuePair { key: VarInt(11), value: Bytes([34, 0]) }])
            ///  right: Err(TrackPropertyValueOutOfRange { key: 34, value: 0 })
            /// ```
            #[test]
            fn a_value_outside_the_range_its_type_allows_is_refused() {
                for &(key, value) in OUT_OF_RANGE.iter().chain($also_refused) {
                    for (where_, run) in [("beside", beside(key, value)), ("inside", inside(key, value))]
                    {
                        assert_eq!(
                            tail_of(&subscribe_ok(&run)),
                            Err(CodecError::TrackPropertyValueOutOfRange { key, value }),
                            "type {key:#x} value {value} {where_} the immutable block must be refused",
                        );
                    }
                }
            }

            /// Every value the two ranges admit still decodes, in both places.
            #[test]
            fn every_value_the_ranges_admit_is_carried() {
                for &(key, value) in IN_RANGE {
                    let beside = tail_of(&subscribe_ok(&beside(key, value)))
                        .unwrap_or_else(|e| panic!("type {key:#x} value {value} is legal: {e:?}"));
                    assert_eq!(beside.len(), 1);
                    assert_eq!(beside[0].key.into_inner(), key);

                    let inside = tail_of(&subscribe_ok(&inside(key, value)))
                        .unwrap_or_else(|e| panic!("type {key:#x} value {value} nested: {e:?}"));
                    assert_eq!(inside.len(), 1, "the block is carried whole");
                    assert_eq!(inside[0].key.into_inner(), IMMUTABLE);
                }
            }

            /// A range stated without a consequence is not a close.
            ///
            /// DEFAULT_PUBLISHER_PRIORITY names a range and stops, in the same
            /// section as two entries that each name a consequence. This is what
            /// fails when a table is assembled from ranges rather than from the
            /// sentences that answer them.
            #[test]
            fn a_priority_the_draft_calls_invalid_without_saying_more_is_carried() {
                let tail = tail_of(&subscribe_ok(&beside(DEFAULT_PUBLISHER_PRIORITY, 300)))
                    .expect("no consequence is stated, so the frame is carried");
                assert_eq!(tail.len(), 1);
                assert_eq!(
                    tail[0].value,
                    KvpValue::Varint(VarInt::from_u64(300).unwrap()),
                    "the value reaches the caller unchanged",
                );
            }

            /// A value the decoder refuses is never written.
            ///
            /// The two directions have to agree: a frame this codec emits and
            /// then declines to read is one the peer is required to close the
            /// session over, so the sender's first sign of trouble would be the
            /// session going.
            ///
            /// The buffer is checked as well as the error. Encoding builds the
            /// payload into scratch before copying it out, so a refused message
            /// leaves the caller's buffer exactly as it found it.
            ///
            /// # What it catches
            ///
            /// Without the check on the encode path:
            ///
            /// ```text
            /// assertion `left == right` failed: type 0x22 value 0 must not be written
            ///   left: Ok(())
            ///  right: Err(TrackPropertyValueOutOfRange { key: 34, value: 0 })
            /// ```
            #[test]
            fn a_value_the_decoder_refuses_is_never_written() {
                for &(key, value) in OUT_OF_RANGE.iter().chain($also_refused) {
                    let mut inner: SubscribeOk = $shell;
                    inner.$field = vec![KeyValuePair {
                        key: VarInt::from_u64(key).unwrap(),
                        value: KvpValue::Varint(VarInt::from_u64(value).unwrap()),
                    }];
                    let message = ControlMessage::SubscribeOk(inner);
                    let mut wire = Vec::new();
                    let result = message.encode(&mut wire);
                    assert_eq!(
                        result,
                        Err(CodecError::TrackPropertyValueOutOfRange { key, value }),
                        "type {key:#x} value {value} must not be written",
                    );
                    assert!(wire.is_empty(), "a refused message writes no bytes");
                }
            }

            /// An Immutable block whose contents are not Key-Value-Pairs is
            /// carried, not refused.
            ///
            /// Reading inside the block is a permission — "Relays MAY decode and
            /// view" it — so bytes this codec cannot parse go to the caller
            /// intact. Refusing here would end sessions over a shape the draft
            /// answers with something other than a close, and would do it to
            /// every peer using the block for anything this codec has not been
            /// taught.
            #[test]
            fn an_immutable_block_this_codec_cannot_read_is_carried() {
                // A single 0xFF opens an eight-byte varint with one byte behind
                // it, so the nested run cannot be parsed under either profile.
                let mut run = Vec::new();
                kvp_bytes(&mut 0, IMMUTABLE, &[0xFF], &mut run);

                let tail = tail_of(&subscribe_ok(&run)).expect("unreadable is not the same as illegal");
                assert_eq!(tail.len(), 1);
                assert_eq!(tail[0].value, KvpValue::Bytes(vec![0xFF]));
            }

            /// An unreadable Immutable block does not stop the entries after it
            /// from being checked.
            ///
            /// The test above says such a block is carried. This one says what
            /// "carried" is scoped to. The walk answered the unreadable block by
            /// returning from the whole function, so every property *after* it
            /// went unexamined — and a peer wanting an out-of-range value
            /// carried had only to put a one-byte 0xFF block in front of it.
            /// That is the same opt-out the module note describes one level up,
            /// reached from the other side.
            ///
            /// The draft scopes the rule to the block and not to its
            /// neighbours. Draft-16 Section 11.2: "A Track is considered
            /// malformed ... if any of the following conditions are detected:
            /// ... A Key-Value-Pair cannot be parsed." Drafts 17 and later keep
            /// the sentence under Immutable Properties. Nothing in it reaches
            /// the run outside.
            ///
            /// # What it catches
            ///
            /// With `Err(_) => return Ok(())` restored, the out-of-range value
            /// is handed to the caller behind the block that hid it:
            ///
            /// ```text
            /// assertion `left == right` failed: type 0x22 value 0 behind an unreadable block must still be refused
            ///   left: Ok([KeyValuePair { key: VarInt(11), value: Bytes([255]) }, KeyValuePair { key: VarInt(34), value: Varint(VarInt(0)) }])
            ///  right: Err(TrackPropertyValueOutOfRange { key: 34, value: 0 })
            /// ```
            #[test]
            fn an_unreadable_immutable_block_does_not_shield_what_follows_it() {
                // Types in a run ascend, so "after the block" is only a place a
                // Type above 0x0B can be. That is where both entries with a
                // range live; draft-16's extra DELIVERY_TIMEOUT row is 0x02 and
                // can only precede the block, which is the case the gate above
                // already covers.
                let after: Vec<_> = OUT_OF_RANGE
                    .iter()
                    .chain($also_refused)
                    .filter(|&&(key, _)| key > IMMUTABLE)
                    .collect();
                assert!(!after.is_empty(), "something must be able to follow the block");

                for &&(key, value) in &after {
                    let mut run = Vec::new();
                    let mut prev = 0;
                    // The same one-byte block as above: 0xFF opens a varint
                    // eight bytes wide with nothing behind it.
                    kvp_bytes(&mut prev, IMMUTABLE, &[0xFF], &mut run);
                    kvp_varint(&mut prev, key, value, &mut run);

                    assert_eq!(
                        tail_of(&subscribe_ok(&run)),
                        Err(CodecError::TrackPropertyValueOutOfRange { key, value }),
                        "type {key:#x} value {value} behind an unreadable block \
                         must still be refused",
                    );
                }
            }
        }
    };
}

#[cfg(feature = "draft16")]
track_property_range_gate!(
    draft16,
    "draft16",
    draft16,
    track_extensions,
    put_varint = fn put_varint(v: u64, out: &mut Vec<u8>) {
        VarInt::from_u64(v).expect("fixture value fits a varint").encode(out);
    },
    prelude = |payload: &mut Vec<u8>| {
        // Request ID, Track Alias, then an empty Parameters list.
        put_varint(1, payload);
        put_varint(7, payload);
        put_varint(0, payload);
    },
    shell = SubscribeOk {
        request_id: VarInt::from_u64(1).unwrap(),
        track_alias: VarInt::from_u64(7).unwrap(),
        parameters: Vec::new(),
        track_extensions: Vec::new(),
    },
    // DELIVERY_TIMEOUT (0x02), Section 11.1: "DELIVERY_TIMEOUT, if present, MUST
    // contain a value greater than 0. If an endpoint receives a
    // DELIVERY_TIMEOUT equal to 0 it MUST close the session with
    // PROTOCOL_VIOLATION." Draft-16 states this in both registries at once, the
    // Message Parameter half being `parameter_value_ranges.rs`'s business.
    // Draft-17 renamed the type to OBJECT_DELIVERY_TIMEOUT and states no range,
    // so this row is one draft wide and stops here.
    also_refused = &[(0x02, 0)]
);

#[cfg(feature = "draft17")]
track_property_range_gate!(
    draft17,
    "draft17",
    draft17,
    track_properties,
    put_varint = fn put_varint(v: u64, out: &mut Vec<u8>) {
        VarInt::from_u64_moqt(v).encode_moqt::<Moqt17>(out);
    },
    prelude = |payload: &mut Vec<u8>| {
        // Draft-17 dropped SUBSCRIBE_OK's Request ID: Track Alias, then an
        // empty Parameters list.
        put_varint(7, payload);
        put_varint(0, payload);
    },
    shell = SubscribeOk {
        track_alias: VarInt::from_u64(7).unwrap(),
        parameters: Vec::new(),
        track_properties: Vec::new(),
    },
    // Draft-16's DELIVERY_TIMEOUT range does not survive the rename to
    // OBJECT_DELIVERY_TIMEOUT, which states none.
    also_refused = &[]
);

#[cfg(feature = "draft18")]
track_property_range_gate!(
    draft18,
    "draft18",
    draft18,
    track_properties,
    put_varint = fn put_varint(v: u64, out: &mut Vec<u8>) {
        VarInt::from_u64_moqt(v).encode_moqt::<Moqt18>(out);
    },
    prelude = |payload: &mut Vec<u8>| {
        put_varint(7, payload);
        put_varint(0, payload);
    },
    shell = SubscribeOk {
        track_alias: VarInt::from_u64(7).unwrap(),
        parameters: Vec::new(),
        track_properties: Vec::new(),
    },
    // Draft-16's DELIVERY_TIMEOUT range does not survive the rename to
    // OBJECT_DELIVERY_TIMEOUT, which states none.
    also_refused = &[]
);

#[cfg(feature = "draft19")]
track_property_range_gate!(
    draft19,
    "draft19",
    draft19,
    track_properties,
    put_varint = fn put_varint(v: u64, out: &mut Vec<u8>) {
        VarInt::from_u64_moqt(v).encode_moqt::<Moqt18>(out);
    },
    prelude = |payload: &mut Vec<u8>| {
        put_varint(7, payload);
        put_varint(0, payload);
    },
    shell = SubscribeOk {
        track_alias: VarInt::from_u64(7).unwrap(),
        parameters: Vec::new(),
        track_properties: Vec::new(),
    },
    // Draft-16's DELIVERY_TIMEOUT range does not survive the rename to
    // OBJECT_DELIVERY_TIMEOUT, which states none.
    also_refused = &[]
);

// Draft-20's Property registry is draft-19's unchanged — Section 15.8 Table 14
// has the same nine rows — and SUBSCRIBE_OK frames its Track Properties the
// same way, so the same gate answers for it. The provisional table beside it
// did move (TIMESTAMP 0x06 to 0x10, VIDEO_FRAME_MARKING 0x0A to 0x09, and 0x0A
// reassigned to ENCRYPTED_LIST), but those rows belong to other documents and
// this codec carries them as opaque Key-Value-Pairs.
#[cfg(feature = "draft20")]
track_property_range_gate!(
    draft20,
    "draft20",
    draft20,
    track_properties,
    put_varint = fn put_varint(v: u64, out: &mut Vec<u8>) {
        VarInt::from_u64_moqt(v).encode_moqt::<Moqt18>(out);
    },
    prelude = |payload: &mut Vec<u8>| {
        put_varint(7, payload);
        put_varint(0, payload);
    },
    shell = SubscribeOk {
        track_alias: VarInt::from_u64(7).unwrap(),
        parameters: Vec::new(),
        track_properties: Vec::new(),
    },
    also_refused = &[]
);

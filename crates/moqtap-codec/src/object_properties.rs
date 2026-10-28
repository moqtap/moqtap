//! Object Properties, called Extension Headers before draft-17, read as an
//! ordered list.
//!
//! The object readers keep a property block as the bytes the wire carried, and
//! a relay forwards those untouched. [`parse_object_properties`] reads them by
//! the rules of one draft. A list rather than a map: a Type may repeat, an odd
//! Type carries bytes rather than a number, and a Type the draft does not name
//! still has to be kept.

use crate::error::CodecError;
use crate::kvp::KvpError;
use crate::varint::{Moqt17, Moqt18, VarInt, VarIntError};
use crate::version::{DraftVersion, VarIntEncoding};

/// What separates one draft's property block from another's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyRules {
    /// The varint every Type, Length and even value is written in.
    pub varint: VarIntEncoding,
    /// Whether each Type is a delta from the one before it rather than
    /// absolute.
    pub delta_types: bool,
    /// The largest value an odd Type may carry, where the draft sets one.
    pub max_value_len: Option<u64>,
    /// The Type that holds Immutable Properties (Immutable Extensions), where
    /// the draft defines one.
    pub immutable_type: Option<u64>,
}

impl PropertyRules {
    /// The rules `draft` gives its object property block. `None` on draft-07,
    /// whose objects carry none.
    pub fn for_draft(draft: DraftVersion) -> Option<Self> {
        let varint = draft.varint_encoding();
        let rules = |delta_types, max_value_len, immutable_type| {
            Some(Self { varint, delta_types, max_value_len, immutable_type })
        };
        match draft {
            DraftVersion::Draft07 => None,
            // Draft-08 and 09 Section 8.1.1.2, draft-10 Section 9.1.1.2.
            DraftVersion::Draft08 | DraftVersion::Draft09 | DraftVersion::Draft10 => {
                rules(false, None, None)
            }
            // Section 1.3.2: "The maximum length of a value is 2^16-1 bytes."
            DraftVersion::Draft11 | DraftVersion::Draft12 | DraftVersion::Draft13 => {
                rules(false, Some(MAX_VALUE_LEN), None)
            }
            // Section 1.4.2. Immutable Extensions: draft-14 Section 11.2,
            // draft-15 Section 11.1.
            DraftVersion::Draft14 | DraftVersion::Draft15 => {
                rules(false, Some(MAX_VALUE_LEN), Some(IMMUTABLE))
            }
            // Delta Types: draft-16 Section 1.4.2, drafts 17-20 Section 1.4.3,
            // drafts 21-22 Section 8.3. Immutable Extensions: draft-16 Section
            // 11.2; Immutable Properties: draft-17 Section 11.6, drafts 18-20
            // Section 12.7, drafts 21-22 Section 10.7.
            DraftVersion::Draft16
            | DraftVersion::Draft17
            | DraftVersion::Draft18
            | DraftVersion::Draft19
            | DraftVersion::Draft20
            | DraftVersion::Draft21
            | DraftVersion::Draft22 => rules(true, Some(MAX_VALUE_LEN), Some(IMMUTABLE)),
        }
    }
}

const MAX_VALUE_LEN: u64 = 0xFFFF;
const IMMUTABLE: u64 = 0x0B;

/// One property, as the wire carried it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectProperty<'a> {
    /// The absolute Type, with any delta encoding resolved.
    pub property_type: u64,
    /// The value.
    pub value: PropertyValue<'a>,
}

/// A property's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyValue<'a> {
    /// The value of an even Type.
    Varint(u64),
    /// The value of an odd Type, borrowed from the block.
    Bytes(&'a [u8]),
    /// Immutable Properties: the raw value, and its contents read by the same
    /// rules.
    Immutable {
        /// The value as the wire carried it.
        bytes: &'a [u8],
        /// The properties inside it, in wire order.
        properties: Vec<ObjectProperty<'a>>,
    },
}

/// Read `block`, the contents of one object's property block without its
/// length or count prefix, by the rules of `draft`.
///
/// Refuses a block the draft calls malformed: a property that runs past the
/// end of the block, including a varint cut short inside it, and Immutable
/// Properties inside Immutable Properties are
/// [`CodecError::MalformedObjectProperties`]; an odd value longer than the
/// draft allows is [`KvpError::ValueTooLong`]; a Type delta past 2^64 - 1 is
/// [`CodecError::KeyDeltaOverflow`].
pub fn parse_object_properties(
    draft: DraftVersion,
    block: &[u8],
) -> Result<Vec<ObjectProperty<'_>>, CodecError> {
    match PropertyRules::for_draft(draft) {
        Some(rules) => parse_with(&rules, block),
        None if block.is_empty() => Ok(Vec::new()),
        None => Err(malformed(0, format!("{draft:?} objects carry no properties"))),
    }
}

/// [`parse_object_properties`] with the rules given directly.
pub fn parse_with<'a>(
    rules: &PropertyRules,
    block: &'a [u8],
) -> Result<Vec<ObjectProperty<'a>>, CodecError> {
    read_run(rules, block, 0, false)
}

fn read_run<'a>(
    rules: &PropertyRules,
    run: &'a [u8],
    base: usize,
    nested: bool,
) -> Result<Vec<ObjectProperty<'a>>, CodecError> {
    let mut properties = Vec::new();
    let mut cursor = run;
    let mut prev_type = 0u64;
    while !cursor.is_empty() {
        let offset = base + (run.len() - cursor.len());
        let raw = read_varint(rules, &mut cursor, offset)?;
        let property_type = if rules.delta_types {
            prev_type.checked_add(raw).ok_or(CodecError::KeyDeltaOverflow(prev_type, raw))?
        } else {
            raw
        };
        prev_type = property_type;

        if property_type % 2 == 0 {
            let value = read_varint(rules, &mut cursor, offset)?;
            properties.push(ObjectProperty { property_type, value: PropertyValue::Varint(value) });
            continue;
        }

        let len = read_varint(rules, &mut cursor, offset)?;
        if rules.max_value_len.is_some_and(|max| len > max) {
            return Err(KvpError::ValueTooLong(usize::try_from(len).unwrap_or(usize::MAX)).into());
        }
        let Some(bytes) = usize::try_from(len).ok().and_then(|len| cursor.get(..len)) else {
            return Err(malformed(
                offset,
                format!(
                    "property 0x{property_type:02X} claims {len} bytes but the property block has \
                     {} left",
                    cursor.len()
                ),
            ));
        };
        let value_base = base + (run.len() - cursor.len());
        cursor = &cursor[bytes.len()..];

        let value = if rules.immutable_type == Some(property_type) {
            if nested {
                return Err(malformed(
                    offset,
                    "Immutable Properties inside Immutable Properties".to_string(),
                ));
            }
            PropertyValue::Immutable {
                bytes,
                properties: read_run(rules, bytes, value_base, true)?,
            }
        } else {
            PropertyValue::Bytes(bytes)
        };
        properties.push(ObjectProperty { property_type, value });
    }
    Ok(properties)
}

fn read_varint(
    rules: &PropertyRules,
    cursor: &mut &[u8],
    offset: usize,
) -> Result<u64, CodecError> {
    let decoded = match rules.varint {
        VarIntEncoding::Rfc9000 => VarInt::decode(cursor),
        VarIntEncoding::Moqt17 => VarInt::decode_moqt::<Moqt17>(cursor),
        VarIntEncoding::Moqt18 => VarInt::decode_moqt::<Moqt18>(cursor),
    };
    match decoded {
        Ok(v) => Ok(v.into_inner()),
        // The block's length is already known, so this is a property running
        // past it rather than input still to arrive.
        Err(VarIntError::UnexpectedEnd) => {
            Err(malformed(offset, "a property runs past the end of the property block".to_string()))
        }
        Err(e) => Err(e.into()),
    }
}

fn malformed(offset: usize, detail: String) -> CodecError {
    CodecError::MalformedObjectProperties { offset, detail }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(draft: DraftVersion) -> PropertyRules {
        PropertyRules::for_draft(draft).unwrap()
    }

    #[test]
    fn reads_odd_even_and_repeated_types_in_wire_order() {
        // draft-17 subgroup-properties-odd-type: 0x0D = cafe, then delta 0x2F to 0x3C = 2.
        let props =
            parse_with(&rules(DraftVersion::Draft17), &[0x0d, 0x02, 0xca, 0xfe, 0x2f, 0x02])
                .unwrap();
        assert_eq!(
            props,
            vec![
                ObjectProperty { property_type: 0x0d, value: PropertyValue::Bytes(&[0xca, 0xfe]) },
                ObjectProperty { property_type: 0x3c, value: PropertyValue::Varint(2) },
            ]
        );
        let repeated =
            parse_with(&rules(DraftVersion::Draft17), &[0x0d, 0x01, 0xaa, 0x00, 0x01, 0xbb])
                .unwrap();
        assert_eq!(repeated.len(), 2);
        assert_eq!(repeated[1].property_type, 0x0d);
    }

    #[test]
    fn absolute_types_before_draft_16() {
        let props = parse_with(&rules(DraftVersion::Draft15), &[0x3c, 0x01, 0x3e, 0x02]).unwrap();
        assert_eq!(props[1].property_type, 0x3e);
        let delta = parse_with(&rules(DraftVersion::Draft16), &[0x3c, 0x01, 0x02, 0x02]).unwrap();
        assert_eq!(delta[1].property_type, 0x3e);
    }

    #[test]
    fn immutable_contents_restart_their_delta_at_zero() {
        let props = parse_with(&rules(DraftVersion::Draft17), &[0x0b, 0x02, 0x3c, 0x02]).unwrap();
        let PropertyValue::Immutable { bytes, properties } = &props[0].value else {
            panic!("0xB not read as Immutable Properties: {props:?}");
        };
        assert_eq!(*bytes, &[0x3c, 0x02]);
        assert_eq!(properties[0].property_type, 0x3c);
        // Draft-13 has no Immutable Extensions, so 0xB is plain bytes there.
        let plain = parse_with(&rules(DraftVersion::Draft13), &[0x0b, 0x02, 0x3c, 0x02]).unwrap();
        assert_eq!(plain[0].value, PropertyValue::Bytes(&[0x3c, 0x02]));
    }

    #[test]
    fn refuses_what_the_drafts_call_malformed() {
        let d17 = rules(DraftVersion::Draft17);
        // draft-17 subgroup-properties-overrun.
        assert!(matches!(
            parse_with(&d17, &[0x0d, 0x05, 0xca]),
            Err(CodecError::MalformedObjectProperties { offset: 0, .. })
        ));
        // Even value cut short.
        assert!(matches!(
            parse_with(&d17, &[0x3c, 0x02, 0x3c]),
            Err(CodecError::MalformedObjectProperties { offset: 2, .. })
        ));
        assert!(matches!(
            parse_with(&d17, &[0x0b, 0x03, 0x0b, 0x01, 0x00]),
            Err(CodecError::MalformedObjectProperties { offset: 2, .. })
        ));
        let mut too_long = vec![0x0d];
        VarInt::from_u64_moqt(0x10000).encode_moqt::<Moqt17>(&mut too_long);
        assert_eq!(
            parse_with(&d17, &too_long),
            Err(CodecError::Kvp(KvpError::ValueTooLong(0x10000)))
        );
        let mut overflow = vec![0x3c, 0x01];
        VarInt::from_u64_moqt(u64::MAX).encode_moqt::<Moqt17>(&mut overflow);
        assert_eq!(parse_with(&d17, &overflow), Err(CodecError::KeyDeltaOverflow(0x3c, u64::MAX)));
        // No limit before draft-11.
        assert!(matches!(
            parse_with(&rules(DraftVersion::Draft10), &[0x0d, 0x80, 0x01, 0x00, 0x00]),
            Err(CodecError::MalformedObjectProperties { .. })
        ));
    }

    #[test]
    fn draft_07_has_no_block() {
        assert_eq!(parse_object_properties(DraftVersion::Draft07, &[]), Ok(Vec::new()));
        assert!(parse_object_properties(DraftVersion::Draft07, &[0x02, 0x00]).is_err());
    }
}

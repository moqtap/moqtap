//! A decoded control message as a tree of named fields.
//!
//! [`AnyControlMessage::fields`](crate::dispatch::AnyControlMessage::fields)
//! turns any draft's `ControlMessage` into a [`FieldMap`] whose keys are the
//! field names that draft gives them. The names are the drafts' own, in
//! snake_case, and the field order is the order the draft defines — so a
//! reader that has never heard of a message can still show it, and two drafts
//! that spell the same concept differently keep their own spelling. The
//! per-draft `fields` modules are what it dispatches to.
//!
//! # Why a tree of the crate's own making
//!
//! The obvious return types are `serde_json::Value` and `ciborium::Value`, and
//! this crate depends on neither. A codec that gained a serialization format's
//! value type would make everything downstream carry it, to describe messages
//! that have nothing to do with that format. [`FieldValue`] is `std` and a
//! `Vec`, and each caller renders it into whatever it already writes: the
//! vector tests into JSON, where a varint becomes a decimal string and a byte
//! string becomes hex, and a trace writer into CBOR, where both have a type of
//! their own.
//!
//! That split is also why [`FieldValue::Uint`] and [`FieldValue::Bytes`] are
//! distinct from [`FieldValue::Text`] rather than pre-rendered into it. A
//! converter that flattened them would force every consumer to guess which
//! strings were numbers.

/// Parameter tables more than one draft shares.
///
/// A draft whose parameter handling is its own keeps it in its own `fields.rs`,
/// which is where all but four of them are. Only drafts 07 through 10 share:
/// one message table across all four, and one setup table across the three that
/// dropped ROLE. Anything reachable from a single draft belongs to that draft,
/// or a build of that draft alone compiles code nothing can call.
#[cfg(any(feature = "draft07", feature = "draft08", feature = "draft09", feature = "draft10"))]
pub(crate) mod params;

/// One field's value inside a decoded control message.
///
/// Absent optional fields are omitted from their [`FieldMap`] rather than
/// given a zero: a field the wire never carried and a field carrying zero are
/// different, and only omission can say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    /// A varint or fixed-width integer, widened to `u64`.
    Uint(u64),
    /// A single-bit field.
    Bool(bool),
    /// A field the draft defines as text, or a name for something the draft
    /// leaves opaque — an unknown parameter's key, rendered `0x21`.
    Text(String),
    /// A field the draft leaves as opaque bytes.
    Bytes(Vec<u8>),
    /// A repeated field, in wire order.
    Array(Vec<FieldValue>),
    /// A nested structure — a location, a parameter set, a fetch's payload.
    Map(FieldMap),
}

/// A decoded message's fields, in the order the draft defines them.
///
/// Ordered rather than sorted because the order is information: it is the
/// order the fields appear on the wire, which is what makes a rendering of
/// one message comparable to a rendering of the same message from another
/// implementation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldMap {
    entries: Vec<(String, FieldValue)>,
}

impl FieldMap {
    /// An empty map.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Set `key` to `value`, replacing any value already under that key.
    ///
    /// Replacing rather than appending keeps a duplicate key impossible, which
    /// is what lets a reader index the map. A replaced key keeps its original
    /// position, so a later correction does not reorder the message.
    ///
    /// The key is a `String` rather than an `impl Into<String>` because the
    /// callers write `"request_id".into()`, and a generic bound leaves that
    /// `into` with nothing to infer from.
    pub fn insert(&mut self, key: String, value: FieldValue) {
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((key, value)),
        }
    }

    /// The value under `key`, if the message carried that field.
    pub fn get(&self, key: &str) -> Option<&FieldValue> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The fields, in the order the draft defines them.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &FieldValue)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Whether the message had no fields at all. True for the handful of
    /// messages that are nothing but their type.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many fields the message carried.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl IntoIterator for FieldMap {
    type Item = (String, FieldValue);
    type IntoIter = std::vec::IntoIter<(String, FieldValue)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

/// Render a Key-Value-Pair list as entries, in the order the wire carried them.
///
/// # Why a list and not a map keyed by name
///
/// Every draft models a parameter block as an ordered list of (Type, Value),
/// with types ascending. Rendering it as a map keyed by the draft's name for
/// each type reads better and loses three things:
///
/// * **Repeats.** Two parameter definitions permit a message to carry their
///   type more than once — AUTHORIZATION_TOKEN, and on drafts 19 and 20 the
///   five Range Filters. A map has one slot per name, so two SUBGROUP_FILTERs
///   under different SetIDs became the second one alone: the frame said
///   "Subgroup 1-3 in set 0, or 10-12 in set 1" and the record said "10-12",
///   which is not a narrower reading of the request but a different one.
/// * **Order.** Drafts 16 and later require that "Parameters MUST be serialized
///   in ascending order by Type" and answer a descending pair with a session
///   close. A map has no order, so no vector could state that rule at all.
/// * **Unknown types.** A map has no name to key them under, so each draft
///   invented something: 11 through 14 dropped them, and the later ones parked
///   them in a second, differently-shaped `unknown` array beside the named
///   ones. Two containers for one wire field.
///
/// An entry list has none of those problems and needs no special case for any
/// of them: a repeat is two entries, order is the list's, and an unknown type
/// is an entry without a `name`.
///
/// # The entry
///
/// `type` is always present, as the lowercase hex of the Parameter Type. `name`
/// is present when the draft names that type. Then exactly one of:
///
/// * `value` — the decoded value, when this codec models it. A varint renders
///   as its number, a structure as a nested map.
/// * `raw_hex` — the value's bytes, when it does not.
///
/// An unnamed varint parameter gets `value` rather than `raw_hex`, because a
/// varint's value *is* its content and there are no bytes to show. That case
/// used to be written as `length`, which was the varint's value under a key
/// naming something else entirely.
pub(crate) fn kvp_entries<F>(params: &[crate::kvp::KeyValuePair], mut render: F) -> FieldValue
where
    F: FnMut(u64, &crate::kvp::KvpValue) -> (Option<&'static str>, Option<FieldValue>),
{
    use crate::kvp::KvpValue;

    let mut out = Vec::with_capacity(params.len());
    for p in params {
        let key = p.key.into_inner();
        let (name, value) = render(key, &p.value);

        let mut entry = FieldMap::new();
        entry.insert("type".into(), FieldValue::Text(format!("0x{key:x}")));
        if let Some(name) = name {
            entry.insert("name".into(), FieldValue::Text(name.to_string()));
        }
        match (value, &p.value) {
            (Some(value), _) => entry.insert("value".into(), value),
            (None, KvpValue::Varint(v)) => {
                entry.insert("value".into(), FieldValue::Uint(v.into_inner()))
            }
            (None, KvpValue::Bytes(b)) => {
                entry.insert("raw_hex".into(), FieldValue::Bytes(b.clone()))
            }
        }
        out.push(FieldValue::Map(entry));
    }
    FieldValue::Array(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kvp::{KeyValuePair, KvpValue};
    use crate::varint::VarInt;

    fn pair(key: u64, value: KvpValue) -> KeyValuePair {
        KeyValuePair { key: VarInt::from_u64(key).expect("a fixture key"), value }
    }

    fn field(entry: &FieldValue, name: &str) -> Option<FieldValue> {
        match entry {
            FieldValue::Map(m) => m.get(name).cloned(),
            _ => panic!("an entry is a map"),
        }
    }

    fn entries(value: &FieldValue) -> &[FieldValue] {
        match value {
            FieldValue::Array(items) => items,
            _ => panic!("a KVP list renders as an array"),
        }
    }

    /// A repeat is two entries, which is the whole of the special case.
    ///
    /// The map this replaced had one slot per name, so the first of these
    /// vanished and the second was reported as if it were all the frame
    /// carried.
    #[test]
    fn a_repeated_type_is_two_entries_in_wire_order() {
        let params =
            vec![pair(0x25, KvpValue::Bytes(vec![0x00])), pair(0x25, KvpValue::Bytes(vec![0x01]))];
        let rendered =
            kvp_entries(&params, |key, _| (Some("subgroup_filter"), Some(FieldValue::Uint(key))));
        let items = entries(&rendered);
        assert_eq!(items.len(), 2);
        for entry in items {
            assert_eq!(field(entry, "type"), Some(FieldValue::Text("0x25".into())));
            assert_eq!(field(entry, "name"), Some(FieldValue::Text("subgroup_filter".into())));
        }
    }

    /// Order is the list's, so a descending pair renders as one.
    ///
    /// Drafts 16 and later close the session over a descending pair, and a map
    /// keyed by name could not state the rule because it had no order to be
    /// wrong about.
    #[test]
    fn order_survives_and_is_the_wire_order() {
        let params = vec![
            pair(0x20, KvpValue::Varint(VarInt::from_u64(1).unwrap())),
            pair(0x10, KvpValue::Varint(VarInt::from_u64(2).unwrap())),
        ];
        let rendered = kvp_entries(&params, |_, _| (None, None));
        let items = entries(&rendered);
        assert_eq!(field(&items[0], "type"), Some(FieldValue::Text("0x20".into())));
        assert_eq!(field(&items[1], "type"), Some(FieldValue::Text("0x10".into())));
    }

    /// An unnamed type is an ordinary entry without a `name`, not a second
    /// container beside the named ones.
    #[test]
    fn an_unknown_type_keeps_its_bytes_and_loses_only_its_name() {
        let params = vec![pair(0xf1, KvpValue::Bytes(vec![0xaa, 0xbb]))];
        let rendered = kvp_entries(&params, |_, _| (None, None));
        let entry = &entries(&rendered)[0];
        assert_eq!(field(entry, "type"), Some(FieldValue::Text("0xf1".into())));
        assert_eq!(field(entry, "name"), None);
        assert_eq!(field(entry, "raw_hex"), Some(FieldValue::Bytes(vec![0xaa, 0xbb])));
        assert_eq!(field(entry, "value"), None);
    }

    /// An unnamed *varint* gets `value`, because there are no bytes to show.
    ///
    /// This case used to be written as `length`, holding the varint's value
    /// under a key naming something else entirely.
    #[test]
    fn an_unknown_varint_reports_its_value_rather_than_a_length() {
        let params = vec![pair(0xf0, KvpValue::Varint(VarInt::from_u64(4).unwrap()))];
        let rendered = kvp_entries(&params, |_, _| (None, None));
        let entry = &entries(&rendered)[0];
        assert_eq!(field(entry, "value"), Some(FieldValue::Uint(4)));
        assert_eq!(field(entry, "raw_hex"), None);
        assert_eq!(field(entry, "length"), None);
    }
}

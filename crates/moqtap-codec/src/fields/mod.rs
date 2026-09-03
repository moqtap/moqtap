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

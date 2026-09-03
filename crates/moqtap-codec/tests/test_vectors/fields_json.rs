//! The vectors' JSON rendering of a decoded message's fields.
//!
//! The field structure itself is the crate's, one module per draft under
//! `draftNN::fields`. This is only the last step: how each leaf is spelled in
//! the vector files, which is not how it is spelled anywhere else.
//!
//! Two of those spellings exist because JSON has no type for what the wire
//! carries. A varint is a decimal *string*, since a `u64` past 2^53 does not
//! survive a JSON number in every reader that has to agree on these files. An
//! opaque byte string is hex. A consumer with types of its own — CBOR, say —
//! renders the same [`FieldValue`] tree without either workaround, which is
//! the reason the tree stops short of rendering anything itself.

use moqtap_codec::fields::{FieldMap, FieldValue};
use serde_json::{Map, Value};

/// A decoded message's fields, as the vector files spell them.
pub fn to_json(fields: &FieldMap) -> Value {
    map_to_json(fields)
}

fn map_to_json(fields: &FieldMap) -> Value {
    let mut obj = Map::new();
    for (key, value) in fields.iter() {
        obj.insert(key.to_string(), value_to_json(value));
    }
    Value::Object(obj)
}

fn value_to_json(value: &FieldValue) -> Value {
    match value {
        FieldValue::Uint(n) => Value::String(n.to_string()),
        FieldValue::Bool(b) => Value::Bool(*b),
        FieldValue::Text(s) => Value::String(s.clone()),
        FieldValue::Bytes(b) => Value::String(hex::encode(b)),
        FieldValue::Array(items) => Value::Array(items.iter().map(value_to_json).collect()),
        FieldValue::Map(inner) => map_to_json(inner),
    }
}

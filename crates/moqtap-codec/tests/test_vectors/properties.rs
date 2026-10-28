//! Object property lists checked against the corpus.

use moqtap_codec::object_properties::{parse_object_properties, ObjectProperty, PropertyValue};
use moqtap_codec::version::DraftVersion;
use serde_json::{json, Value};

/// The corpus keys an object's property list under: `extension_headers`
/// through draft-16, `object_properties` from draft-17.
const KEYS: [&str; 2] = ["extension_headers", "object_properties"];

/// `props` as the corpus writes them. An entry's `name` is the corpus's own
/// label for a Type and is not rendered.
pub fn to_json(props: &[ObjectProperty<'_>]) -> Value {
    Value::Array(
        props
            .iter()
            .map(|p| {
                let ty = format!("0x{:x}", p.property_type);
                match &p.value {
                    PropertyValue::Varint(v) => json!({ "type": ty, "value": v.to_string() }),
                    PropertyValue::Bytes(b) => json!({ "type": ty, "raw_hex": hex::encode(b) }),
                    PropertyValue::Immutable { properties, .. } => {
                        json!({ "type": ty, "value": to_json(properties) })
                    }
                }
            })
            .collect(),
    )
}

fn without_names(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(without_names).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(k, _)| k.as_str() != "name")
                .map(|(k, v)| (k.clone(), without_names(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Assert that `block` parses under `draft` to the property list `expected`
/// carries, if it carries one.
pub fn assert_properties(vector_id: &str, draft: DraftVersion, block: &[u8], expected: &Value) {
    let Some(list) = KEYS.iter().find_map(|k| expected.get(*k)) else {
        return;
    };
    let props = parse_object_properties(draft, block)
        .unwrap_or_else(|e| panic!("[{vector_id}] property block does not parse: {e}"));
    assert_eq!(to_json(&props), without_names(list), "[{vector_id}] property list mismatch");
}

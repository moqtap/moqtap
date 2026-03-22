use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;
use serde_json::{Map, Value};

/// Known parameter names for draft-14.
fn d14_param_name(key: u64) -> Option<&'static str> {
    match key {
        0x01 => Some("path"),
        0x02 => Some("max_request_id"),
        0x03 => Some("authorization_token"),
        0x04 => Some("max_auth_token_cache_size"),
        0x05 => Some("authority"),
        _ => None,
    }
}

/// Known parameter names for draft-07 SETUP messages.
fn d07_setup_param_name(key: u64) -> Option<&'static str> {
    match key {
        0x00 => Some("role"),
        0x01 => Some("path"),
        0x02 => Some("max_subscribe_id"),
        _ => None,
    }
}

/// Known parameter names for draft-07 non-SETUP messages.
fn d07_message_param_name(key: u64) -> Option<&'static str> {
    match key {
        0x02 => Some("authorization_info"),
        0x03 => Some("delivery_timeout"),
        _ => None,
    }
}

/// Draft-07 setup varint parameter keys.
fn d07_setup_is_varint(key: u64) -> bool {
    matches!(key, 0x00 | 0x02) // role, max_subscribe_id
}

/// Draft-07 message varint parameter keys.
fn d07_msg_is_varint(key: u64) -> bool {
    matches!(key, 0x03) // delivery_timeout
}

/// Convert KVP list to JSON Value matching test vector format.
pub fn kvp_to_json(params: &[KeyValuePair], name_fn: fn(u64) -> Option<&'static str>) -> Value {
    let mut obj = Map::new();
    let mut unknown = Vec::new();

    for p in params {
        let key = p.key.into_inner();
        if let Some(name) = name_fn(key) {
            match &p.value {
                KvpValue::Varint(v) => {
                    obj.insert(name.to_string(), Value::String(v.into_inner().to_string()));
                }
                KvpValue::Bytes(b) => {
                    obj.insert(
                        name.to_string(),
                        Value::String(String::from_utf8_lossy(b).into_owned()),
                    );
                }
            }
        } else {
            let mut entry = Map::new();
            entry.insert("id".to_string(), Value::String(format!("0x{:x}", key)));
            match &p.value {
                KvpValue::Varint(v) => {
                    entry.insert("length".to_string(), Value::String(v.into_inner().to_string()));
                }
                KvpValue::Bytes(b) => {
                    entry.insert("length".to_string(), Value::String(b.len().to_string()));
                    entry.insert("raw_hex".to_string(), Value::String(hex::encode(b)));
                }
            }
            unknown.push(Value::Object(entry));
        }
    }

    if !unknown.is_empty() {
        obj.insert("unknown".to_string(), Value::Array(unknown));
    }

    Value::Object(obj)
}

pub fn kvp_to_json_d14(params: &[KeyValuePair]) -> Value {
    kvp_to_json(params, d14_param_name)
}

/// Convert draft-07 KVP list to JSON. In draft-07, all values are length-prefixed
/// bytes. For known varint parameters, decode the bytes as a VarInt.
fn kvp_to_json_d07_inner(
    params: &[KeyValuePair],
    name_fn: fn(u64) -> Option<&'static str>,
    is_varint_fn: fn(u64) -> bool,
) -> Value {
    let mut obj = Map::new();
    let mut unknown = Vec::new();

    for p in params {
        let key = p.key.into_inner();
        if let Some(name) = name_fn(key) {
            match &p.value {
                KvpValue::Bytes(b) if is_varint_fn(key) => {
                    let v = VarInt::decode(&mut &b[..]).unwrap();
                    obj.insert(name.to_string(), Value::String(v.into_inner().to_string()));
                }
                KvpValue::Bytes(b) => {
                    obj.insert(
                        name.to_string(),
                        Value::String(String::from_utf8_lossy(b).into_owned()),
                    );
                }
                KvpValue::Varint(v) => {
                    obj.insert(name.to_string(), Value::String(v.into_inner().to_string()));
                }
            }
        } else {
            let mut entry = Map::new();
            entry.insert("id".to_string(), Value::String(format!("0x{:x}", key)));
            match &p.value {
                KvpValue::Bytes(b) => {
                    entry.insert("length".to_string(), Value::String(b.len().to_string()));
                    entry.insert("raw_hex".to_string(), Value::String(hex::encode(b)));
                }
                KvpValue::Varint(v) => {
                    entry.insert("length".to_string(), Value::String(v.into_inner().to_string()));
                }
            }
            unknown.push(Value::Object(entry));
        }
    }

    if !unknown.is_empty() {
        obj.insert("unknown".to_string(), Value::Array(unknown));
    }

    Value::Object(obj)
}

pub fn kvp_to_json_d07_setup(params: &[KeyValuePair]) -> Value {
    kvp_to_json_d07_inner(params, d07_setup_param_name, d07_setup_is_varint)
}

pub fn kvp_to_json_d07(params: &[KeyValuePair]) -> Value {
    kvp_to_json_d07_inner(params, d07_message_param_name, d07_msg_is_varint)
}

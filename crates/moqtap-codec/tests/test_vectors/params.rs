use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;
use serde_json::{Map, Value};

/// Parse draft-14+ authorization_token bytes into structured JSON.
/// Structure: alias_type (varint), [token_alias (varint)?], [token_type (varint), token_value (bytes)?]
/// depending on alias_type (0=DELETE, 1=REGISTER, 2=USE_ALIAS, 3=USE_VALUE).
fn auth_token_to_json_d14(bytes: &[u8]) -> Value {
    let mut buf = bytes;
    let alias_type = match VarInt::decode(&mut buf) {
        Ok(v) => v,
        Err(_) => return Value::String(hex::encode(bytes)),
    };
    let at = alias_type.into_inner();
    let mut o = Map::new();
    o.insert("alias_type".to_string(), Value::String(at.to_string()));
    match at {
        0 | 2 => {
            if let Ok(ta) = VarInt::decode(&mut buf) {
                o.insert("token_alias".to_string(), Value::String(ta.into_inner().to_string()));
            }
        }
        1 => {
            if let Ok(ta) = VarInt::decode(&mut buf) {
                o.insert("token_alias".to_string(), Value::String(ta.into_inner().to_string()));
            }
            if let Ok(tt) = VarInt::decode(&mut buf) {
                o.insert("token_type".to_string(), Value::String(tt.into_inner().to_string()));
            }
            o.insert("token_value".to_string(), Value::String(hex::encode(buf)));
        }
        _ => {
            if let Ok(tt) = VarInt::decode(&mut buf) {
                o.insert("token_type".to_string(), Value::String(tt.into_inner().to_string()));
            }
            o.insert("token_value".to_string(), Value::String(hex::encode(buf)));
        }
    }
    Value::Object(o)
}

/// Known parameter names for draft-14+ SETUP messages.
fn d14_setup_param_name(key: u64) -> Option<&'static str> {
    match key {
        0x01 => Some("path"),
        0x02 => Some("max_request_id"),
        0x03 => Some("authorization_token"),
        0x04 => Some("max_auth_token_cache_size"),
        0x05 => Some("authority"),
        _ => None,
    }
}

/// Known parameter names for draft-14+ non-SETUP messages.
fn d14_msg_param_name(key: u64) -> Option<&'static str> {
    match key {
        0x02 => Some("delivery_timeout"),
        0x03 => Some("authorization_token"),
        0x04 => Some("max_cache_duration"),
        _ => None,
    }
}

/// Kept for backwards compatibility: resolves using SETUP mapping.
#[allow(dead_code)]
fn d14_param_name(key: u64) -> Option<&'static str> {
    d14_setup_param_name(key)
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
        0x04 => Some("max_cache_duration"),
        _ => None,
    }
}

/// Draft-07 setup varint parameter keys.
fn d07_setup_is_varint(key: u64) -> bool {
    matches!(key, 0x00 | 0x02) // role, max_subscribe_id
}

/// Draft-07 message varint parameter keys.
fn d07_msg_is_varint(key: u64) -> bool {
    matches!(key, 0x03 | 0x04) // delivery_timeout, max_cache_duration
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
                    if name == "authorization_token" {
                        obj.insert(name.to_string(), auth_token_to_json_d14(b));
                    } else {
                        obj.insert(
                            name.to_string(),
                            Value::String(String::from_utf8_lossy(b).into_owned()),
                        );
                    }
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
    kvp_to_json(params, d14_msg_param_name)
}

pub fn kvp_to_json_d14_setup(params: &[KeyValuePair]) -> Value {
    kvp_to_json(params, d14_setup_param_name)
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

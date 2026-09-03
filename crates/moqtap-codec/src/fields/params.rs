use crate::fields::FieldValue as Value;
use crate::kvp::{KeyValuePair, KvpValue};
use crate::varint::VarInt;

/// Known parameter names for draft-07 SETUP messages.
#[cfg(feature = "draft07")]
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
#[cfg(feature = "draft07")]
fn d07_setup_is_varint(key: u64) -> bool {
    matches!(key, 0x00 | 0x02) // role, max_subscribe_id
}

/// Known parameter names for SETUP messages in drafts 08 through 10.
///
/// The same two as draft-07 minus ROLE, which those drafts do not define: the
/// word occurs nowhere in the text of any of them, and 0x00 is not given to
/// anything else. Naming it here anyway would report a parameter the sender
/// cannot have meant, and it read the value as an integer that no decoder had
/// checked was one.
#[cfg(any(feature = "draft08", feature = "draft09", feature = "draft10"))]
fn d08_setup_param_name(key: u64) -> Option<&'static str> {
    match key {
        0x01 => Some("path"),
        0x02 => Some("max_subscribe_id"),
        _ => None,
    }
}

/// Setup varint parameter keys for drafts 08 through 10.
#[cfg(any(feature = "draft08", feature = "draft09", feature = "draft10"))]
fn d08_setup_is_varint(key: u64) -> bool {
    key == 0x02 // max_subscribe_id
}

/// Draft-07 message varint parameter keys.
fn d07_msg_is_varint(key: u64) -> bool {
    matches!(key, 0x03 | 0x04) // delivery_timeout, max_cache_duration
}

/// Convert draft-07 KVP list to JSON. In draft-07, all values are length-prefixed
/// bytes. For known varint parameters, decode the bytes as a VarInt.
fn kvp_to_json_d07_inner(
    params: &[KeyValuePair],
    name_fn: fn(u64) -> Option<&'static str>,
    is_varint_fn: fn(u64) -> bool,
) -> Value {
    crate::fields::kvp_entries(params, |key, value| {
        let Some(name) = name_fn(key) else {
            return (None, None);
        };
        let rendered = match value {
            KvpValue::Bytes(b) if is_varint_fn(key) => {
                // The bytes come off the wire and the decoder does not
                // always vouch for them: it refuses a value that is not one
                // varint only for the types the draft in question defines
                // as an integer, and this table is shared by four drafts
                // that do not define the same set. A type one of them
                // dropped arrives unchecked, so a value too short to be a
                // varint reaches here.
                //
                // `None` rather than a refusal: this is what a message
                // carried, not a judgement on whether it was allowed to, and
                // an entry with no `value` reports the bytes under `raw_hex`.
                match VarInt::decode(&mut &b[..]) {
                    Ok(v) => Some(Value::Uint(v.into_inner())),
                    Err(_) => None,
                }
            }
            KvpValue::Bytes(b) => Some(Value::Text(String::from_utf8_lossy(b).into_owned())),
            KvpValue::Varint(v) => Some(Value::Uint(v.into_inner())),
        };
        (Some(name), rendered)
    })
}

#[cfg(feature = "draft07")]
pub fn kvp_to_json_d07_setup(params: &[KeyValuePair]) -> Value {
    kvp_to_json_d07_inner(params, d07_setup_param_name, d07_setup_is_varint)
}

pub fn kvp_to_json_d07(params: &[KeyValuePair]) -> Value {
    kvp_to_json_d07_inner(params, d07_message_param_name, d07_msg_is_varint)
}

/// The setup parameter list of a draft that dropped ROLE.
#[cfg(any(feature = "draft08", feature = "draft09", feature = "draft10"))]
pub fn kvp_to_json_d08_setup(params: &[KeyValuePair]) -> Value {
    kvp_to_json_d07_inner(params, d08_setup_param_name, d08_setup_is_varint)
}

use crate::draft17::message::ControlMessage;
use crate::fields::{FieldMap as Map, FieldValue as Value};
use crate::kvp::{KeyValuePair, KvpValue};
use crate::types::*;
use crate::varint::{Moqt17 as Wire, VarInt};

fn vi(v: u64) -> Value {
    Value::Uint(v)
}

fn ns_to_json(ns: &TrackNamespace) -> Value {
    Value::Array(
        ns.0.iter().map(|e| Value::Text(String::from_utf8_lossy(e).into_owned())).collect(),
    )
}

// Draft-17 known parameter types and their encodings
fn d17_param_name(key: u64) -> Option<&'static str> {
    match key {
        0x02 => Some("delivery_timeout"),
        0x03 => Some("authorization_token"),
        0x04 => Some("rendezvous_timeout"),
        0x08 => Some("expires"),
        0x09 => Some("largest_object"),
        0x10 => Some("forward"),
        0x20 => Some("subscriber_priority"),
        0x21 => Some("subscription_filter"),
        0x22 => Some("group_order"),
        0x32 => Some("new_group_request"),
        _ => None,
    }
}

// Draft-17 setup option names
fn d17_option_name(key: u64) -> Option<&'static str> {
    match key {
        0x01 => Some("path"),
        0x03 => Some("authorization_token"),
        0x04 => Some("max_auth_token_cache_size"),
        0x05 => Some("authority"),
        0x07 => Some("moqt_implementation"),
        _ => None,
    }
}

fn decode_subscription_filter(bytes: &[u8]) -> Value {
    let mut buf = bytes;
    let filter_type = VarInt::decode_moqt::<Wire>(&mut buf).unwrap().into_inner();
    let mut obj = Map::new();
    obj.insert("filter_type".into(), vi(filter_type));
    match filter_type {
        3 => {
            let start_group = VarInt::decode_moqt::<Wire>(&mut buf).unwrap().into_inner();
            let start_object = VarInt::decode_moqt::<Wire>(&mut buf).unwrap().into_inner();
            obj.insert("start_group".into(), vi(start_group));
            obj.insert("start_object".into(), vi(start_object));
        }
        4 => {
            let start_group = VarInt::decode_moqt::<Wire>(&mut buf).unwrap().into_inner();
            let start_object = VarInt::decode_moqt::<Wire>(&mut buf).unwrap().into_inner();
            let end_group = VarInt::decode_moqt::<Wire>(&mut buf).unwrap().into_inner();
            obj.insert("start_group".into(), vi(start_group));
            obj.insert("start_object".into(), vi(start_object));
            obj.insert("end_group".into(), vi(end_group));
        }
        _ => {}
    }
    Value::Map(obj)
}

fn auth_token_to_json_d17(bytes: &[u8]) -> Value {
    let mut buf = bytes;
    let alias_type = match VarInt::decode_moqt::<Wire>(&mut buf) {
        Ok(v) => v,
        Err(_) => return Value::Bytes(bytes.to_vec()),
    };
    let at = alias_type.into_inner();
    let mut o = Map::new();
    o.insert("alias_type".into(), vi(at));
    match at {
        0 | 2 => {
            if let Ok(ta) = VarInt::decode_moqt::<Wire>(&mut buf) {
                o.insert("token_alias".into(), vi(ta.into_inner()));
            }
        }
        1 => {
            if let Ok(ta) = VarInt::decode_moqt::<Wire>(&mut buf) {
                o.insert("token_alias".into(), vi(ta.into_inner()));
            }
            if let Ok(tt) = VarInt::decode_moqt::<Wire>(&mut buf) {
                o.insert("token_type".into(), vi(tt.into_inner()));
            }
            // Draft-17: token_value is length-prefixed.
            let tv = match VarInt::decode_moqt::<Wire>(&mut buf) {
                Ok(len) => {
                    let n = len.into_inner() as usize;
                    if buf.len() >= n {
                        &buf[..n]
                    } else {
                        buf
                    }
                }
                Err(_) => buf,
            };
            o.insert("token_value".into(), Value::Bytes(tv.to_vec()));
        }
        _ => {
            if let Ok(tt) = VarInt::decode_moqt::<Wire>(&mut buf) {
                o.insert("token_type".into(), vi(tt.into_inner()));
            }
            let tv = match VarInt::decode_moqt::<Wire>(&mut buf) {
                Ok(len) => {
                    let n = len.into_inner() as usize;
                    if buf.len() >= n {
                        &buf[..n]
                    } else {
                        buf
                    }
                }
                Err(_) => buf,
            };
            o.insert("token_value".into(), Value::Bytes(tv.to_vec()));
        }
    }
    Value::Map(o)
}

fn decode_largest_object(bytes: &[u8]) -> Value {
    let mut buf = bytes;
    let group = VarInt::decode_moqt::<Wire>(&mut buf).unwrap().into_inner();
    let object = VarInt::decode_moqt::<Wire>(&mut buf).unwrap().into_inner();
    let mut obj = Map::new();
    obj.insert("group".into(), vi(group));
    obj.insert("object".into(), vi(object));
    Value::Map(obj)
}

fn params_to_json(params: &[KeyValuePair]) -> Value {
    crate::fields::kvp_entries(params, |key, value| {
        let Some(name) = d17_param_name(key) else {
            return (None, None);
        };
        let rendered = match (value, key) {
            (KvpValue::Bytes(b), 0x21) => decode_subscription_filter(b),
            (KvpValue::Bytes(b), 0x09) => decode_largest_object(b),
            (KvpValue::Bytes(b), _) if name == "authorization_token" => auth_token_to_json_d17(b),
            (KvpValue::Varint(v), _) => vi(v.into_inner()),
            (KvpValue::Bytes(b), _) => Value::Text(String::from_utf8_lossy(b).into_owned()),
        };
        (Some(name), Some(rendered))
    })
}

fn options_to_json(options: &[KeyValuePair]) -> Value {
    crate::fields::kvp_entries(options, |key, value| {
        let Some(name) = d17_option_name(key) else {
            return (None, None);
        };
        let rendered = match value {
            KvpValue::Varint(v) => vi(v.into_inner()),
            KvpValue::Bytes(b) if name == "authorization_token" => auth_token_to_json_d17(b),
            KvpValue::Bytes(b) => Value::Text(String::from_utf8_lossy(b).into_owned()),
        };
        (Some(name), Some(rendered))
    })
}

fn d17_track_prop_name(key: u64) -> Option<&'static str> {
    match key {
        0x02 => Some("delivery_timeout"),
        0x04 => Some("max_cache_duration"),
        0x0b => Some("immutable_properties"),
        0x0e => Some("default_publisher_priority"),
        0x22 => Some("default_publisher_group_order"),
        0x30 => Some("dynamic_groups"),
        _ => None,
    }
}

fn track_props_to_json(props: &[KeyValuePair]) -> Value {
    crate::fields::kvp_entries(props, |key, value| {
        let name = d17_track_prop_name(key);
        let rendered = match value {
            KvpValue::Varint(v) => Some(vi(v.into_inner())),
            // A property this draft does not name keeps its bytes rather than
            // a name invented from its type, which is what an entry's absent
            // `name` already says.
            KvpValue::Bytes(_) => None,
        };
        (name, rendered)
    })
}

/// This draft's field names for a decoded control message.
///
/// Keys are the names this draft gives its fields, in the order it defines
/// them. An optional field the message did not carry is absent rather than
/// zero.
pub fn message_fields(msg: &ControlMessage) -> Map {
    let obj = match msg {
        ControlMessage::Setup(m) => {
            let mut o = Map::new();
            o.insert("options".into(), options_to_json(&m.options));
            o
        }
        ControlMessage::GoAway(m) => {
            let mut o = Map::new();
            o.insert(
                "new_session_uri".into(),
                Value::Text(String::from_utf8_lossy(&m.new_session_uri).into_owned()),
            );
            o.insert("timeout".into(), vi(m.timeout.into_inner()));
            o
        }
        ControlMessage::RequestOk(m) => {
            let mut o = Map::new();
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o
        }
        ControlMessage::RequestError(m) => {
            let mut o = Map::new();
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert("retry_interval".into(), vi(m.retry_interval.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::Subscribe(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert(
                "required_request_id_delta".into(),
                vi(m.required_request_id_delta.into_inner()),
            );
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::Text(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o
        }
        ControlMessage::SubscribeOk(m) => {
            let mut o = Map::new();
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o.insert("track_properties".into(), track_props_to_json(&m.track_properties));
            o
        }
        ControlMessage::RequestUpdate(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert(
                "required_request_id_delta".into(),
                vi(m.required_request_id_delta.into_inner()),
            );
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o
        }
        ControlMessage::Publish(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert(
                "required_request_id_delta".into(),
                vi(m.required_request_id_delta.into_inner()),
            );
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::Text(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o.insert("track_properties".into(), track_props_to_json(&m.track_properties));
            o
        }
        ControlMessage::PublishOk(m) => {
            let mut o = Map::new();
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o
        }
        ControlMessage::PublishDone(m) => {
            let mut o = Map::new();
            o.insert("status_code".into(), vi(m.status_code.into_inner()));
            o.insert("stream_count".into(), vi(m.stream_count.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::PublishNamespace(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert(
                "required_request_id_delta".into(),
                vi(m.required_request_id_delta.into_inner()),
            );
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o
        }
        ControlMessage::Namespace(m) => {
            let mut o = Map::new();
            o.insert("namespace_suffix".into(), ns_to_json(&m.namespace_suffix));
            o
        }
        ControlMessage::NamespaceDone(m) => {
            let mut o = Map::new();
            o.insert("namespace_suffix".into(), ns_to_json(&m.namespace_suffix));
            o
        }
        ControlMessage::SubscribeNamespace(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert(
                "required_request_id_delta".into(),
                vi(m.required_request_id_delta.into_inner()),
            );
            o.insert("namespace_prefix".into(), ns_to_json(&m.namespace_prefix));
            o.insert("subscribe_options".into(), vi(m.subscribe_options.into_inner()));
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o
        }
        ControlMessage::TrackStatus(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert(
                "required_request_id_delta".into(),
                vi(m.required_request_id_delta.into_inner()),
            );
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::Text(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o
        }
        ControlMessage::Fetch(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert(
                "required_request_id_delta".into(),
                vi(m.required_request_id_delta.into_inner()),
            );
            o.insert("fetch_type".into(), vi(m.fetch_type as u64));
            match &m.fetch_payload {
                crate::draft17::message::FetchPayload::Standalone {
                    track_namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                } => {
                    o.insert("track_namespace".into(), ns_to_json(track_namespace));
                    o.insert(
                        "track_name".into(),
                        Value::Text(String::from_utf8_lossy(track_name).into_owned()),
                    );
                    o.insert("start_group".into(), vi(start_group.into_inner()));
                    o.insert("start_object".into(), vi(start_object.into_inner()));
                    o.insert("end_group".into(), vi(end_group.into_inner()));
                    o.insert("end_object".into(), vi(end_object.into_inner()));
                }
                crate::draft17::message::FetchPayload::Joining {
                    joining_request_id,
                    joining_start,
                } => {
                    o.insert("joining_request_id".into(), vi(joining_request_id.into_inner()));
                    o.insert("joining_start".into(), vi(joining_start.into_inner()));
                }
            }
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o
        }
        ControlMessage::FetchOk(m) => {
            let mut o = Map::new();
            o.insert("end_of_track".into(), vi(m.end_of_track as u64));
            o.insert("end_group".into(), vi(m.end_group.into_inner()));
            o.insert("end_object".into(), vi(m.end_object.into_inner()));
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o.insert("track_properties".into(), track_props_to_json(&m.track_properties));
            o
        }
        ControlMessage::PublishBlocked(m) => {
            let mut o = Map::new();
            o.insert("namespace_suffix".into(), ns_to_json(&m.namespace_suffix));
            o.insert(
                "track_name".into(),
                Value::Text(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o
        }
    };
    obj
}

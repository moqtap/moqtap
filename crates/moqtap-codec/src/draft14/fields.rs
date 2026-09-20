use crate::draft14::message::{ControlMessage, FetchPayload};
use crate::fields::{FieldMap as Map, FieldValue as Value};
use crate::types::*;

use crate::kvp::{KeyValuePair, KvpValue};
use crate::varint::VarInt;

fn vi(v: u64) -> Value {
    Value::Uint(v)
}

fn ns_to_json(ns: &TrackNamespace) -> Value {
    Value::Array(
        ns.0.iter().map(|e| Value::Text(String::from_utf8_lossy(e).into_owned())).collect(),
    )
}

fn loc_to_json(loc: &Location) -> Value {
    let mut o = Map::new();
    o.insert("group".into(), vi(loc.group.into_inner()));
    o.insert("object".into(), vi(loc.object.into_inner()));
    Value::Map(o)
}

/// Parse draft-14+ authorization_token bytes into structured JSON.
/// Structure: alias_type (varint), [token_alias (varint)?], [token_type (varint), token_value (bytes)?]
/// depending on alias_type (0=DELETE, 1=REGISTER, 2=USE_ALIAS, 3=USE_VALUE).
fn auth_token_to_json_d14(bytes: &[u8]) -> Value {
    let mut buf = bytes;
    let alias_type = match VarInt::decode(&mut buf) {
        Ok(v) => v,
        Err(_) => return Value::Bytes(bytes.to_vec()),
    };
    let at = alias_type.into_inner();
    let mut o = Map::new();
    o.insert("alias_type".to_string(), Value::Uint(at));
    match at {
        0 | 2 => {
            if let Ok(ta) = VarInt::decode(&mut buf) {
                o.insert("token_alias".to_string(), Value::Uint(ta.into_inner()));
            }
        }
        1 => {
            if let Ok(ta) = VarInt::decode(&mut buf) {
                o.insert("token_alias".to_string(), Value::Uint(ta.into_inner()));
            }
            if let Ok(tt) = VarInt::decode(&mut buf) {
                o.insert("token_type".to_string(), Value::Uint(tt.into_inner()));
            }
            o.insert("token_value".to_string(), Value::Bytes(buf.to_vec()));
        }
        _ => {
            if let Ok(tt) = VarInt::decode(&mut buf) {
                o.insert("token_type".to_string(), Value::Uint(tt.into_inner()));
            }
            o.insert("token_value".to_string(), Value::Bytes(buf.to_vec()));
        }
    }
    Value::Map(o)
}

/// Known parameter names for draft-14+ SETUP messages.
///
/// # 0x05 has two names in this draft, and this table gives it one
///
/// Draft-14 Section 9.3.2.1 assigns 0x05 to AUTHORITY and Section 9.3.2.6
/// assigns 0x05 to MOQT_IMPLEMENTATION. That is a defect in the draft, not a
/// gap in this table: the two sections are five subsections apart in one
/// document and both spell "Parameter Type 0x05". Draft-15 Section 9.3.1.6
/// moves MOQT_IMPLEMENTATION to 0x07 and the collision ends there — its change
/// log names the move outright, "Change MOQT IMPLEMENTATION code point to 0x7".
///
/// Both values are opaque bytes — an RFC3986 authority component and a
/// "UTF-8 encoded string" naming an implementation — so nothing in the frame
/// separates them. A renderer handed a draft-14 setup 0x05 has no way to know
/// which parameter it is looking at, and there is no reading of the draft that
/// gives it one.
///
/// **This answers `authority`, deliberately, and the name is not a claim that
/// the sender meant AUTHORITY.** Three reasons, in the order they decided it:
///
/// 1. The shared vector corpus names it `authority` — `transport/draft14/codec/
///    messages/client-setup.json`, the `authority-param` case — and that file is
///    the contract between this codec and every other implementation reading the
///    same vectors. A rendering that disagreed with it would be a rendering no
///    other reader produces.
/// 2. AUTHORITY is the half with consequences attached. Draft-14 assigns
///    INVALID_AUTHORITY (0x19) and MALFORMED_AUTHORITY (0x1A) and says what a
///    server does with a bad one; MOQT_IMPLEMENTATION is informational and the
///    draft's own security section still carries a TODO about it. Reading an
///    implementation string as an authority shows a reader a field they can act
///    on; the reverse hides one.
/// 3. Naming it for both — `authority_or_moqt_implementation`, say — would put
///    the ambiguity in a place no consumer can use it, since the name is what a
///    trace keys on, and would break every reader keyed on the corpus while
///    still not saying which parameter arrived.
///
/// So the ambiguity is recorded here rather than in the rendered field, and a
/// reader who needs to tell the two apart has to do it from the value: an
/// authority is a host, and an implementation string is a name and a version.
/// `setup_option_name` cannot help — asking draft-15 about a draft-14 0x05
/// answers `authority` as well, because draft-15 keeps AUTHORITY at 0x05 and
/// only moved the other one.
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

/// Convert KVP list to JSON Value matching test vector format.
fn kvp_to_json(params: &[KeyValuePair], name_fn: fn(u64) -> Option<&'static str>) -> Value {
    crate::fields::kvp_entries(params, |key, value| {
        let Some(name) = name_fn(key) else {
            return (None, None);
        };
        let rendered = match value {
            KvpValue::Varint(v) => Value::Uint(v.into_inner()),
            KvpValue::Bytes(b) if name == "authorization_token" => auth_token_to_json_d14(b),
            KvpValue::Bytes(b) => Value::Text(String::from_utf8_lossy(b).into_owned()),
        };
        (Some(name), Some(rendered))
    })
}

fn kvp_to_json_d14(params: &[KeyValuePair]) -> Value {
    kvp_to_json(params, d14_msg_param_name)
}

pub(crate) fn kvp_to_json_d14_setup(params: &[KeyValuePair]) -> Value {
    kvp_to_json(params, d14_setup_param_name)
}

/// This draft's field names for a decoded control message.
///
/// Keys are the names this draft gives its fields, in the order it defines
/// them. An optional field the message did not carry is absent rather than
/// zero.
pub fn message_fields(msg: &ControlMessage) -> Map {
    let obj = match msg {
        ControlMessage::ClientSetup(m) => {
            let mut o = Map::new();
            o.insert(
                "supported_versions".into(),
                Value::Array(m.supported_versions.iter().map(|v| vi(v.into_inner())).collect()),
            );
            o.insert("parameters".into(), kvp_to_json_d14_setup(&m.parameters));
            o
        }
        ControlMessage::ServerSetup(m) => {
            let mut o = Map::new();
            o.insert("selected_version".into(), vi(m.selected_version.into_inner()));
            o.insert("parameters".into(), kvp_to_json_d14_setup(&m.parameters));
            o
        }
        ControlMessage::GoAway(m) => {
            let mut o = Map::new();
            o.insert(
                "new_session_uri".into(),
                Value::Text(String::from_utf8_lossy(&m.new_session_uri).into_owned()),
            );
            o
        }
        ControlMessage::MaxRequestId(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o
        }
        ControlMessage::RequestsBlocked(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.maximum_request_id.into_inner()));
            o
        }
        ControlMessage::Subscribe(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::Text(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("forward".into(), vi(m.forward as u64));
            o.insert("filter_type".into(), vi(m.filter_type as u64));
            if let Some(loc) = &m.start_location {
                o.insert("start_group".into(), vi(loc.group.into_inner()));
                o.insert("start_object".into(), vi(loc.object.into_inner()));
            }
            if let Some(eg) = &m.end_group {
                o.insert("end_group".into(), vi(eg.into_inner()));
            }
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::SubscribeOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o.insert("expires".into(), vi(m.expires.into_inner()));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("content_exists".into(), vi(m.content_exists as u64));
            if let Some(loc) = &m.largest_location {
                o.insert("largest_location".into(), loc_to_json(loc));
            }
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::SubscribeError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::SubscribeUpdate(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("subscription_request_id".into(), vi(m.subscription_request_id.into_inner()));
            o.insert("start_group".into(), vi(m.start_location.group.into_inner()));
            o.insert("start_object".into(), vi(m.start_location.object.into_inner()));
            o.insert("end_group".into(), vi(m.end_group.into_inner()));
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("forward".into(), vi(m.forward as u64));
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::Unsubscribe(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o
        }
        ControlMessage::Publish(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::Text(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("content_exists".into(), vi(m.content_exists as u64));
            if let Some(loc) = &m.largest_location {
                o.insert("largest_location".into(), loc_to_json(loc));
            }
            o.insert("forward".into(), vi(m.forward as u64));
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::PublishOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("forward".into(), vi(m.forward as u64));
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("filter_type".into(), vi(m.filter_type as u64));
            if let Some(loc) = &m.start_location {
                o.insert("start_group".into(), vi(loc.group.into_inner()));
                o.insert("start_object".into(), vi(loc.object.into_inner()));
            }
            if let Some(eg) = &m.end_group {
                o.insert("end_group".into(), vi(eg.into_inner()));
            }
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::PublishError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::PublishDone(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
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
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::PublishNamespaceOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o
        }
        ControlMessage::PublishNamespaceError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::PublishNamespaceDone(m) => {
            let mut o = Map::new();
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o
        }
        ControlMessage::PublishNamespaceCancel(m) => {
            let mut o = Map::new();
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::SubscribeNamespace(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("namespace_prefix".into(), ns_to_json(&m.track_namespace));
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::SubscribeNamespaceOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o
        }
        ControlMessage::SubscribeNamespaceError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::UnsubscribeNamespace(m) => {
            let mut o = Map::new();
            o.insert("track_namespace_prefix".into(), ns_to_json(&m.track_namespace_prefix));
            o
        }
        ControlMessage::Fetch(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("fetch_type".into(), vi(m.fetch_type as u64));
            match &m.fetch_payload {
                FetchPayload::Standalone {
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
                FetchPayload::Joining { joining_request_id, joining_start } => {
                    o.insert("joining_request_id".into(), vi(joining_request_id.into_inner()));
                    o.insert("joining_start".into(), vi(joining_start.into_inner()));
                }
            }
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::FetchOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("end_of_track".into(), vi(m.end_of_track as u64));
            o.insert("end_location".into(), loc_to_json(&m.end_location));
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::FetchError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::FetchCancel(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o
        }
        ControlMessage::TrackStatus(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::Text(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("forward".into(), vi(m.forward as u64));
            o.insert("filter_type".into(), vi(m.filter_type as u64));
            if let Some(loc) = &m.start_location {
                o.insert("start_group".into(), vi(loc.group.into_inner()));
                o.insert("start_object".into(), vi(loc.object.into_inner()));
            }
            if let Some(eg) = &m.end_group {
                o.insert("end_group".into(), vi(eg.into_inner()));
            }
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::TrackStatusOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o.insert("expires".into(), vi(m.expires.into_inner()));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("content_exists".into(), vi(m.content_exists as u64));
            if let Some(loc) = &m.largest_location {
                o.insert("largest_location".into(), loc_to_json(loc));
            }
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::TrackStatusError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
    };
    obj
}

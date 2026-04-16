use moqtap_codec::draft12::message::*;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;
use serde_json::{Map, Value};

fn vi(v: u64) -> Value {
    Value::String(v.to_string())
}

fn ns_to_json(ns: &TrackNamespace) -> Value {
    Value::Array(
        ns.0.iter().map(|e| Value::String(String::from_utf8_lossy(e).into_owned())).collect(),
    )
}

fn loc_to_json(loc: &Location) -> Value {
    let mut o = Map::new();
    o.insert("group".into(), vi(loc.group.into_inner()));
    o.insert("object".into(), vi(loc.object.into_inner()));
    Value::Object(o)
}

fn auth_token_to_json(bytes: &[u8]) -> Value {
    let mut buf = bytes;
    let alias_type = VarInt::decode(&mut buf).unwrap();
    let token_type = VarInt::decode(&mut buf).unwrap();
    let token_value = buf;
    let mut o = Map::new();
    o.insert("alias_type".into(), vi(alias_type.into_inner()));
    o.insert("token_type".into(), vi(token_type.into_inner()));
    o.insert("token_value".into(), Value::String(hex::encode(token_value)));
    Value::Object(o)
}

fn kvp_to_json_setup(params: &[KeyValuePair]) -> Value {
    let mut obj = Map::new();
    for p in params {
        let key = p.key.into_inner();
        match (key, &p.value) {
            (0x01, KvpValue::Bytes(b)) => {
                obj.insert("path".into(), Value::String(String::from_utf8_lossy(b).into_owned()));
            }
            (0x02, KvpValue::Varint(v)) => {
                obj.insert("max_request_id".into(), vi(v.into_inner()));
            }
            _ => {}
        }
    }
    Value::Object(obj)
}

fn kvp_to_json_msg(params: &[KeyValuePair]) -> Value {
    let mut obj = Map::new();
    for p in params {
        let key = p.key.into_inner();
        match (key, &p.value) {
            (0x03, KvpValue::Bytes(b)) => {
                obj.insert("authorization_token".into(), auth_token_to_json(b));
            }
            (0x02, KvpValue::Varint(v)) => {
                obj.insert("delivery_timeout".into(), vi(v.into_inner()));
            }
            (0x04, KvpValue::Varint(v)) => {
                obj.insert("max_cache_duration".into(), vi(v.into_inner()));
            }
            _ => {}
        }
    }
    Value::Object(obj)
}

pub fn message_to_json(msg: &ControlMessage) -> Value {
    let obj = match msg {
        ControlMessage::ClientSetup(m) => {
            let mut o = Map::new();
            o.insert(
                "supported_versions".into(),
                Value::Array(m.supported_versions.iter().map(|v| vi(v.into_inner())).collect()),
            );
            o.insert("parameters".into(), kvp_to_json_setup(&m.parameters));
            o
        }
        ControlMessage::ServerSetup(m) => {
            let mut o = Map::new();
            o.insert("selected_version".into(), vi(m.selected_version.into_inner()));
            o.insert("parameters".into(), kvp_to_json_setup(&m.parameters));
            o
        }
        ControlMessage::GoAway(m) => {
            let mut o = Map::new();
            o.insert(
                "new_session_uri".into(),
                Value::String(String::from_utf8_lossy(&m.new_session_uri).into_owned()),
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
            o.insert("maximum_request_id".into(), vi(m.maximum_request_id.into_inner()));
            o
        }
        ControlMessage::Subscribe(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::String(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("group_order".into(), vi(m.group_order.into_inner()));
            o.insert("forward".into(), vi(m.forward.into_inner()));
            o.insert("filter_type".into(), vi(m.filter_type.into_inner()));
            if let Some(sg) = &m.start_group {
                o.insert("start_group".into(), vi(sg.into_inner()));
            }
            if let Some(so) = &m.start_object {
                o.insert("start_object".into(), vi(so.into_inner()));
            }
            if let Some(eg) = &m.end_group {
                o.insert("end_group".into(), vi(eg.into_inner()));
            }
            o.insert("parameters".into(), kvp_to_json_msg(&m.parameters));
            o
        }
        ControlMessage::SubscribeOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o.insert("expires".into(), vi(m.expires.into_inner()));
            o.insert("group_order".into(), vi(m.group_order.into_inner()));
            o.insert("content_exists".into(), vi(m.content_exists.into_inner()));
            if let Some(loc) = &m.largest_location {
                o.insert("largest_location".into(), loc_to_json(loc));
            }
            o.insert("parameters".into(), kvp_to_json_msg(&m.parameters));
            o
        }
        ControlMessage::SubscribeError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::SubscribeUpdate(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("start_group".into(), vi(m.start_group.into_inner()));
            o.insert("start_object".into(), vi(m.start_object.into_inner()));
            o.insert("end_group".into(), vi(m.end_group.into_inner()));
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("forward".into(), vi(m.forward.into_inner()));
            o.insert("parameters".into(), kvp_to_json_msg(&m.parameters));
            o
        }
        ControlMessage::SubscribeDone(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("status_code".into(), vi(m.status_code.into_inner()));
            o.insert("stream_count".into(), vi(m.stream_count.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::Unsubscribe(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o
        }
        ControlMessage::Announce(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert("parameters".into(), kvp_to_json_msg(&m.parameters));
            o
        }
        ControlMessage::AnnounceOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o
        }
        ControlMessage::AnnounceError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::AnnounceCancel(m) => {
            let mut o = Map::new();
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::Unannounce(m) => {
            let mut o = Map::new();
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o
        }
        ControlMessage::SubscribeAnnounces(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_namespace_prefix".into(), ns_to_json(&m.track_namespace_prefix));
            o.insert("parameters".into(), kvp_to_json_msg(&m.parameters));
            o
        }
        ControlMessage::SubscribeAnnouncesOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o
        }
        ControlMessage::SubscribeAnnouncesError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::UnsubscribeAnnounces(m) => {
            let mut o = Map::new();
            o.insert("track_namespace_prefix".into(), ns_to_json(&m.track_namespace_prefix));
            o
        }
        ControlMessage::TrackStatusRequest(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::String(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("parameters".into(), kvp_to_json_msg(&m.parameters));
            o
        }
        ControlMessage::TrackStatus(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("status_code".into(), vi(m.status_code.into_inner()));
            o.insert("largest_location".into(), loc_to_json(&m.largest_location));
            o.insert("parameters".into(), kvp_to_json_msg(&m.parameters));
            o
        }
        ControlMessage::Fetch(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("group_order".into(), vi(m.group_order.into_inner()));
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
                        Value::String(String::from_utf8_lossy(track_name).into_owned()),
                    );
                    o.insert("start_group".into(), vi(start_group.into_inner()));
                    o.insert("start_object".into(), vi(start_object.into_inner()));
                    o.insert("end_group".into(), vi(end_group.into_inner()));
                    o.insert("end_object".into(), vi(end_object.into_inner()));
                }
                FetchPayload::Joining { joining_subscribe_id, joining_start } => {
                    o.insert("joining_subscribe_id".into(), vi(joining_subscribe_id.into_inner()));
                    o.insert("joining_start".into(), vi(joining_start.into_inner()));
                }
            }
            o.insert("parameters".into(), kvp_to_json_msg(&m.parameters));
            o
        }
        ControlMessage::FetchOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("group_order".into(), vi(m.group_order.into_inner()));
            o.insert("end_of_track".into(), vi(m.end_of_track.into_inner()));
            o.insert("end_location".into(), loc_to_json(&m.end_location));
            o.insert("parameters".into(), kvp_to_json_msg(&m.parameters));
            o
        }
        ControlMessage::FetchError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::FetchCancel(m) => {
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
                Value::String(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o.insert("group_order".into(), vi(m.group_order.into_inner()));
            o.insert("content_exists".into(), vi(m.content_exists.into_inner()));
            if let Some(loc) = &m.largest_location {
                o.insert("largest_location".into(), loc_to_json(loc));
            }
            o.insert("forward".into(), vi(m.forward.into_inner()));
            o.insert("parameters".into(), kvp_to_json_msg(&m.parameters));
            o
        }
        ControlMessage::PublishOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("forward".into(), vi(m.forward.into_inner()));
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("group_order".into(), vi(m.group_order.into_inner()));
            o.insert("filter_type".into(), vi(m.filter_type.into_inner()));
            if let Some(sg) = &m.start_group {
                o.insert("start_group".into(), vi(sg.into_inner()));
            }
            if let Some(so) = &m.start_object {
                o.insert("start_object".into(), vi(so.into_inner()));
            }
            if let Some(eg) = &m.end_group {
                o.insert("end_group".into(), vi(eg.into_inner()));
            }
            o.insert("parameters".into(), kvp_to_json_msg(&m.parameters));
            o
        }
        ControlMessage::PublishError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
    };
    Value::Object(obj)
}

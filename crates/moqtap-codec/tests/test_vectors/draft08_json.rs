use moqtap_codec::draft08::message::ControlMessage;
use moqtap_codec::types::*;
use serde_json::{Map, Value};

use super::params::{kvp_to_json_d07, kvp_to_json_d07_setup};

fn vi(v: u64) -> Value {
    Value::String(v.to_string())
}

fn ns_to_json(ns: &TrackNamespace) -> Value {
    Value::Array(
        ns.0.iter().map(|e| Value::String(String::from_utf8_lossy(e).into_owned())).collect(),
    )
}

pub fn message_to_json(msg: &ControlMessage) -> Value {
    let obj = match msg {
        ControlMessage::ClientSetup(m) => {
            let mut o = Map::new();
            o.insert(
                "supported_versions".into(),
                Value::Array(m.supported_versions.iter().map(|v| vi(v.into_inner())).collect()),
            );
            o.insert("parameters".into(), kvp_to_json_d07_setup(&m.parameters));
            o
        }
        ControlMessage::ServerSetup(m) => {
            let mut o = Map::new();
            o.insert("selected_version".into(), vi(m.selected_version.into_inner()));
            o.insert("parameters".into(), kvp_to_json_d07_setup(&m.parameters));
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
        ControlMessage::MaxSubscribeId(m) => {
            let mut o = Map::new();
            o.insert("subscribe_id".into(), vi(m.subscribe_id.into_inner()));
            o
        }
        ControlMessage::SubscribesBlocked(m) => {
            let mut o = Map::new();
            o.insert("maximum_subscribe_id".into(), vi(m.maximum_subscribe_id.into_inner()));
            o
        }
        ControlMessage::Subscribe(m) => {
            let mut o = Map::new();
            o.insert("subscribe_id".into(), vi(m.subscribe_id.into_inner()));
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::String(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
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
            o.insert("parameters".into(), kvp_to_json_d07(&m.parameters));
            o
        }
        ControlMessage::SubscribeOk(m) => {
            let mut o = Map::new();
            o.insert("subscribe_id".into(), vi(m.subscribe_id.into_inner()));
            o.insert("expires".into(), vi(m.expires.into_inner()));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("content_exists".into(), vi(m.content_exists as u64));
            if let Some(gid) = &m.largest_group_id {
                o.insert("largest_group_id".into(), vi(gid.into_inner()));
            }
            if let Some(oid) = &m.largest_object_id {
                o.insert("largest_object_id".into(), vi(oid.into_inner()));
            }
            o.insert("parameters".into(), kvp_to_json_d07(&m.parameters));
            o
        }
        ControlMessage::SubscribeError(m) => {
            let mut o = Map::new();
            o.insert("subscribe_id".into(), vi(m.subscribe_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o
        }
        ControlMessage::SubscribeUpdate(m) => {
            let mut o = Map::new();
            o.insert("subscribe_id".into(), vi(m.subscribe_id.into_inner()));
            o.insert("start_group".into(), vi(m.start_group.into_inner()));
            o.insert("start_object".into(), vi(m.start_object.into_inner()));
            o.insert("end_group".into(), vi(m.end_group.into_inner()));
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("parameters".into(), kvp_to_json_d07(&m.parameters));
            o
        }
        ControlMessage::SubscribeDone(m) => {
            let mut o = Map::new();
            o.insert("subscribe_id".into(), vi(m.subscribe_id.into_inner()));
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
            o.insert("subscribe_id".into(), vi(m.subscribe_id.into_inner()));
            o
        }
        ControlMessage::Announce(m) => {
            let mut o = Map::new();
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert("parameters".into(), kvp_to_json_d07(&m.parameters));
            o
        }
        ControlMessage::AnnounceOk(m) => {
            let mut o = Map::new();
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o
        }
        ControlMessage::AnnounceError(m) => {
            let mut o = Map::new();
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
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
            o.insert("track_namespace_prefix".into(), ns_to_json(&m.track_namespace_prefix));
            o.insert("parameters".into(), kvp_to_json_d07(&m.parameters));
            o
        }
        ControlMessage::SubscribeAnnouncesOk(m) => {
            let mut o = Map::new();
            o.insert("track_namespace_prefix".into(), ns_to_json(&m.track_namespace_prefix));
            o
        }
        ControlMessage::SubscribeAnnouncesError(m) => {
            let mut o = Map::new();
            o.insert("track_namespace_prefix".into(), ns_to_json(&m.track_namespace_prefix));
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
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::String(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o
        }
        ControlMessage::TrackStatus(m) => {
            let mut o = Map::new();
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::String(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("status_code".into(), vi(m.status_code.into_inner()));
            o.insert("last_group_id".into(), vi(m.last_group_id.into_inner()));
            o.insert("last_object_id".into(), vi(m.last_object_id.into_inner()));
            o
        }
        ControlMessage::Fetch(m) => {
            let mut o = Map::new();
            o.insert("subscribe_id".into(), vi(m.subscribe_id.into_inner()));
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("fetch_type".into(), vi(m.fetch_type as u64));
            if let Some(ns) = &m.track_namespace {
                o.insert("track_namespace".into(), ns_to_json(ns));
            }
            if let Some(name) = &m.track_name {
                o.insert(
                    "track_name".into(),
                    Value::String(String::from_utf8_lossy(name).into_owned()),
                );
            }
            if let Some(sg) = &m.start_group {
                o.insert("start_group".into(), vi(sg.into_inner()));
            }
            if let Some(so) = &m.start_object {
                o.insert("start_object".into(), vi(so.into_inner()));
            }
            if let Some(eg) = &m.end_group {
                o.insert("end_group".into(), vi(eg.into_inner()));
            }
            if let Some(eo) = &m.end_object {
                o.insert("end_object".into(), vi(eo.into_inner()));
            }
            if let Some(jsi) = &m.joining_subscribe_id {
                o.insert("joining_subscribe_id".into(), vi(jsi.into_inner()));
            }
            if let Some(pgo) = &m.preceding_group_offset {
                o.insert("preceding_group_offset".into(), vi(pgo.into_inner()));
            }
            o.insert("parameters".into(), kvp_to_json_d07(&m.parameters));
            o
        }
        ControlMessage::FetchOk(m) => {
            let mut o = Map::new();
            o.insert("subscribe_id".into(), vi(m.subscribe_id.into_inner()));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("end_of_track".into(), vi(m.end_of_track as u64));
            o.insert("largest_group_id".into(), vi(m.largest_group_id.into_inner()));
            o.insert("largest_object_id".into(), vi(m.largest_object_id.into_inner()));
            o.insert("parameters".into(), kvp_to_json_d07(&m.parameters));
            o
        }
        ControlMessage::FetchError(m) => {
            let mut o = Map::new();
            o.insert("subscribe_id".into(), vi(m.subscribe_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::FetchCancel(m) => {
            let mut o = Map::new();
            o.insert("subscribe_id".into(), vi(m.subscribe_id.into_inner()));
            o
        }
    };
    Value::Object(obj)
}

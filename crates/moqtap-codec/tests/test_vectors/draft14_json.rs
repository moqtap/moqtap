use moqtap_codec::draft14::message::ControlMessage;
use moqtap_codec::types::*;
use serde_json::{Map, Value};

use super::params::kvp_to_json_d14;

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
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::ServerSetup(m) => {
            let mut o = Map::new();
            o.insert("selected_version".into(), vi(m.selected_version.into_inner()));
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
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
            o.insert("request_id".into(), vi(m.maximum_request_id.into_inner()));
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
                o.insert("largest_group".into(), vi(loc.group.into_inner()));
                o.insert("largest_object".into(), vi(loc.object.into_inner()));
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
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::SubscribeUpdate(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
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
                Value::String(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("forward".into(), vi(m.forward as u64));
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::PublishOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o.insert("forward".into(), vi(m.forward as u64));
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
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
        ControlMessage::PublishDone(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("status_code".into(), vi(m.status_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
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
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::PublishNamespaceError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::PublishNamespaceDone(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("status_code".into(), vi(m.status_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::PublishNamespaceCancel(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
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
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::SubscribeNamespaceError(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::UnsubscribeNamespace(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o
        }
        ControlMessage::Fetch(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::String(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("start_group".into(), vi(m.start_group.into_inner()));
            o.insert("start_object".into(), vi(m.start_object.into_inner()));
            o.insert("end_group".into(), vi(m.end_group.into_inner()));
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::FetchOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o.insert("end_of_track".into(), vi(m.end_of_track.into_inner()));
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
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
        ControlMessage::TrackStatus(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::String(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("parameters".into(), kvp_to_json_d14(&m.parameters));
            o
        }
        ControlMessage::TrackStatusOk(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("status_code".into(), vi(m.status_code.into_inner()));
            if let Some(loc) = &m.largest_location {
                o.insert("largest_group".into(), vi(loc.group.into_inner()));
                o.insert("largest_object".into(), vi(loc.object.into_inner()));
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
                Value::String(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
    };
    Value::Object(obj)
}

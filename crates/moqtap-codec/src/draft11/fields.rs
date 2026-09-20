use crate::draft11::message::*;
use crate::fields::{FieldMap as Map, FieldValue as Value};
use crate::kvp::{KeyValuePair, KvpValue};
use crate::types::*;
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

/// Parse an authorization_token byte value into JSON.
///
/// Draft-11 Section 8.2.1.1 Figure 4 gives the Token four fields, three of them
/// optional, with the first deciding which of the others are on the wire:
///
/// ```text
/// TOKEN {
///   Alias Type (i),
///   [Token Alias (i),]
///   [Token Type (i),]
///   [Token Value (..)]
/// }
/// ```
///
/// Table 3 spells out which: DELETE (0x0) and USE_ALIAS (0x2) are "an Alias but
/// no Type or Value", REGISTER (0x1) is "an Alias, a Type and a Value", and
/// USE_VALUE (0x3) is "no Alias and there is a Type and Value". So the second
/// varint is the Alias on three of the four forms and the Token Type on one.
///
/// So the second varint has to be read against the Alias Type rather than
/// named ahead of it: `token_type` is its name on USE_VALUE alone, and on the
/// other three forms it is the Alias. [`crate::auth_token::TokenAliasType`] is
/// the same table in code, and draft-13's renderer branches on it the same
/// way.
///
/// # What a value it cannot read renders as
///
/// The raw bytes, as `fields::params` and every other draft's renderer do.
/// Field extraction runs on a message that has already decoded, so it has no
/// refusal to give: what a peer sent is what there is to show.
///
/// Draft-11 is the one draft where nothing public can hand this a value its own
/// decoder did not already hold to the structure. `check_authorization_tokens`
/// runs `AuthorizationToken::decode` over every 0x01 on the way in, and this
/// draft alone keeps the token out of the setup namespace — so
/// `setup_option_name`, which exists precisely to hand one draft bytes another
/// draft's peer sent, answers `path` for a setup 0x01 and never arrives here.
/// The reads are `if let` anyway, because that guarantee belongs to two
/// functions in a different file and a renderer that panics on the bytes it was
/// handed is wrong whether or not today's call graph reaches it. Drafts 12 and
/// 13, which moved the token to 0x03 in both namespaces, are where the same
/// `unwrap` was reachable.
fn auth_token_to_json(bytes: &[u8]) -> Value {
    let mut buf = bytes;
    let Ok(alias_type) = VarInt::decode(&mut buf) else {
        return Value::Bytes(bytes.to_vec());
    };
    let at = alias_type.into_inner();
    let mut o = Map::new();
    o.insert("alias_type".into(), vi(at));
    match at {
        // DELETE, USE_ALIAS: an Alias and nothing else.
        0 | 2 => {
            if let Ok(ta) = VarInt::decode(&mut buf) {
                o.insert("token_alias".into(), vi(ta.into_inner()));
            }
        }
        // REGISTER: an Alias, a Type and a Value.
        1 => {
            if let Ok(ta) = VarInt::decode(&mut buf) {
                o.insert("token_alias".into(), vi(ta.into_inner()));
            }
            if let Ok(tt) = VarInt::decode(&mut buf) {
                o.insert("token_type".into(), vi(tt.into_inner()));
            }
            o.insert("token_value".into(), Value::Bytes(buf.to_vec()));
        }
        // USE_VALUE (0x3), and any Alias Type this draft does not assign: a
        // Type and a Value. An unassigned code has no serialization at all —
        // Section 8.2.1.1 calls the Alias Type "an integer defining both the
        // serialization and the processing behavior of the receiver" — so this
        // arm is a guess. It is the one that shows the most of an unreadable
        // value rather than the one the draft endorses.
        _ => {
            if let Ok(tt) = VarInt::decode(&mut buf) {
                o.insert("token_type".into(), vi(tt.into_inner()));
            }
            o.insert("token_value".into(), Value::Bytes(buf.to_vec()));
        }
    }
    Value::Map(o)
}

/// Convert draft-11 KVP list to JSON for setup messages.
///
/// The three Setup Parameters Section 8.3.2 defines, and no more. There is
/// deliberately no `authorization_token` here: draft-11 numbers that parameter
/// 0x01 in the version-specific namespace only, where 0x01 among Setup
/// Parameters is PATH, and Section 8.2.1 says outright that "since Setup
/// parameters use a separate namespace, it is impossible for these parameters
/// to appear in Setup messages". Draft-12 Section 8.3.2.4 is where the token
/// joins this list.
pub(crate) fn kvp_to_json_setup(params: &[KeyValuePair]) -> Value {
    crate::fields::kvp_entries(params, |key, value| match (key, value) {
        (0x01, KvpValue::Bytes(b)) => {
            (Some("path"), Some(Value::Text(String::from_utf8_lossy(b).into_owned())))
        }
        (0x02, KvpValue::Varint(v)) => (Some("max_request_id"), Some(vi(v.into_inner()))),
        // Section 8.3.2.3, and 0x04 rather than 0x03: draft-11 leaves 0x03
        // unassigned in this namespace.
        (0x04, KvpValue::Varint(v)) => {
            (Some("max_auth_token_cache_size"), Some(vi(v.into_inner())))
        }
        _ => (None, None),
    })
}

/// Convert draft-11 KVP list to JSON for non-setup messages.
fn kvp_to_json_msg(params: &[KeyValuePair]) -> Value {
    crate::fields::kvp_entries(params, |key, value| match (key, value) {
        (0x01, KvpValue::Bytes(b)) => (Some("authorization_token"), Some(auth_token_to_json(b))),
        (0x02, KvpValue::Varint(v)) => (Some("delivery_timeout"), Some(vi(v.into_inner()))),
        (0x04, KvpValue::Varint(v)) => (Some("max_cache_duration"), Some(vi(v.into_inner()))),
        _ => (None, None),
    })
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
            o.insert("maximum_request_id".into(), vi(m.maximum_request_id.into_inner()));
            o
        }
        ControlMessage::Subscribe(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::Text(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("forward".into(), vi(m.forward as u64));
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
            o.insert("expires".into(), vi(m.expires.into_inner()));
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("content_exists".into(), vi(m.content_exists as u64));
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
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o.insert("track_alias".into(), vi(m.track_alias.into_inner()));
            o
        }
        ControlMessage::SubscribeUpdate(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("start_group".into(), vi(m.start_group.into_inner()));
            o.insert("start_object".into(), vi(m.start_object.into_inner()));
            o.insert("end_group".into(), vi(m.end_group.into_inner()));
            o.insert("subscriber_priority".into(), vi(m.subscriber_priority as u64));
            o.insert("forward".into(), vi(m.forward as u64));
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
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
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
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::AnnounceCancel(m) => {
            let mut o = Map::new();
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert("error_code".into(), vi(m.error_code.into_inner()));
            o.insert(
                "reason_phrase".into(),
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
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
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
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
                Value::Text(String::from_utf8_lossy(&m.track_name).into_owned()),
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
            o.insert("group_order".into(), vi(m.group_order as u64));
            o.insert("end_of_track".into(), vi(m.end_of_track as u64));
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
                Value::Text(String::from_utf8_lossy(&m.reason_phrase).into_owned()),
            );
            o
        }
        ControlMessage::FetchCancel(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o
        }
    };
    obj
}

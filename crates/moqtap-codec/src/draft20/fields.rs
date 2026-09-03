use crate::draft20::message::ControlMessage;
use crate::fields::{FieldMap as Map, FieldValue as Value};
use crate::kvp::{KeyValuePair, KvpValue};
use crate::range_filter::RangeFilter;
use crate::types::*;
use crate::varint::{Moqt18 as Wire, VarInt};

fn vi(v: u64) -> Value {
    Value::Uint(v)
}

fn ns_to_json(ns: &TrackNamespace) -> Value {
    Value::Array(
        ns.0.iter().map(|e| Value::Text(String::from_utf8_lossy(e).into_owned())).collect(),
    )
}

// Draft-20 known parameter types and their encodings. Two rows are new:
// 0x23 FILL_PARAMETERS and 0x35 INCLUDE_PROPERTIES. Nothing was removed or
// renumbered.
fn d20_param_name(key: u64) -> Option<&'static str> {
    match key {
        0x02 => Some("object_delivery_timeout"),
        0x03 => Some("authorization_token"),
        0x04 => Some("rendezvous_timeout"),
        0x06 => Some("subgroup_delivery_timeout"),
        0x08 => Some("expires"),
        0x09 => Some("largest_object"),
        0x0A => Some("fill_timeout"),
        0x10 => Some("forward"),
        0x20 => Some("subscriber_priority"),
        0x21 => Some("location_filter"),
        0x22 => Some("group_order"),
        0x23 => Some("fill_parameters"),
        0x25 => Some("subgroup_filter"),
        0x26 => Some("objectid_filter"),
        0x27 => Some("priority_filter"),
        0x28 => Some("object_property_filter"),
        0x29 => Some("track_property_filter"),
        0x32 => Some("new_group_request"),
        0x34 => Some("track_namespace_prefix"),
        0x35 => Some("include_properties"),
        _ => None,
    }
}

// Draft-20 setup option names — unchanged from draft-19.
fn d20_option_name(key: u64) -> Option<&'static str> {
    match key {
        0x01 => Some("path"),
        0x03 => Some("authorization_token"),
        0x04 => Some("max_auth_token_cache_size"),
        0x05 => Some("authority"),
        0x06 => Some("max_filter_ranges"),
        0x07 => Some("moqt_implementation"),
        0x08 => Some("max_request_updates"),
        _ => None,
    }
}

/// Render a draft-20 Range Filter parameter value: SetID (u8), an optional
/// Property Type (varint, for the Object/Track Property filters), then a
/// sequence of delta-encoded inclusive Start/End range pairs. A zero-length
/// value denotes filter removal (only meaningful in REQUEST_UPDATE).
///
/// Unchanged from draft-19: draft-20 replaced the one-line shorthand of its
/// Section 5.1.3 with proper figures in Section 5.1.4 and changed no codepoint,
/// field order or delta arithmetic.
///
/// # The parse belongs to [`crate::range_filter`], not here
///
/// Draft-20's parameter table gives 0x25-0x29 `LengthPrefixed`, which stores
/// the value verbatim, and `check_location_filters` covers 0x21 and 0x23 and
/// nothing else — so the bytes arriving here are whatever a peer sent, one
/// level down inside `FILL_PARAMETERS` as well as at the top. A parse written
/// out again here read its varints with `unwrap` and resolved its two delta
/// baselines with `+`, on a value where `Buf::has_remaining` promises one more
/// byte and a MoQT varint may need nine. The bare `+` was the worse half: in
/// release it wrapped rather than panicking, and a filter recorded as
/// `start = u64::MAX, end = 0` is a wrong answer that looks like data.
///
/// [`RangeFilter::decode_moqt`] is the same read done once, with `checked_add`
/// on both baselines and a `Malformed` for every field the value ends before.
/// Calling it makes the checked parse the only parse.
///
/// # What a value it cannot read renders as
///
/// The raw bytes. [`message_fields`] answers for a message that has *already*
/// decoded, so refusing is not available to it: the frame is valid and one
/// parameter's value is not. Rendering what arrived is the answer
/// `fields::params` gives in the same situation, and the one this file's own
/// `auth_token_to_json_d20` and `decode_track_namespace_prefix` already give.
///
/// # A filter that parses but breaks a content rule still renders
///
/// [`RangeFilter`] enforces two rules beyond the value's shape — a Publisher
/// Priority range above 255, and a property filter over an odd Property Type.
/// Draft-20 answers both with REQUEST_ERROR rather than a session close, so
/// both arrive here as bytes a peer really sent.
///
/// Those two are exactly the filters whose fields a reader most needs to see,
/// so this renders them and names the rule broken under `violates`, rather
/// than refusing and hiding the offending value inside a hex dump. That is why
/// it decodes with [`RangeFilter::decode_moqt_structure`] and asks
/// [`RangeFilter::check_its_own_types`] separately: a decoder must refuse these
/// values, a renderer must describe them, and the split is by what the caller
/// does with the answer rather than by how much checking it wants.
fn decode_range_filter(bytes: &[u8], parameter_type: u64) -> Value {
    let mut o = Map::new();
    if bytes.is_empty() {
        o.insert("removed".into(), Value::Bool(true));
        return Value::Map(o);
    }
    let Ok(filter) = RangeFilter::decode_moqt_structure::<Wire>(parameter_type, bytes) else {
        return Value::Bytes(bytes.to_vec());
    };
    if let Err(broken) = filter.check_its_own_types() {
        o.insert("violates".into(), Value::Text(broken.to_string()));
    }
    o.insert("set_id".into(), vi(filter.set_id as u64));
    if let Some(property_type) = filter.property_type {
        o.insert("property_type".into(), vi(property_type));
    }
    let ranges = filter
        .ranges
        .iter()
        .map(|range| {
            let mut r = Map::new();
            r.insert("start".into(), vi(range.start));
            if let Some(end) = range.end {
                r.insert("end".into(), vi(end));
            }
            Value::Map(r)
        })
        .collect();
    o.insert("ranges".into(), Value::Array(ranges));
    Value::Map(o)
}

/// Decode a draft-20 LOCATION_FILTER value.
///
/// The Filter Type enum is gone — draft-19's `0x1` Next Group Start, `0x2`
/// Largest Object, `0x3` AbsoluteStart and `0x4` AbsoluteRange — and the shape
/// comes from how many `vi64` fields the value holds instead (Section 5.1.2).
/// The names are positional: one field is `StartGroup`, two adds
/// `StartObject`, three adds `EndGroupDelta`, four adds `EndObject`, and a
/// zero-length value is the filter's removal.
///
/// The fields are decoded through the codec rather than restated here, so this
/// reports what the codec read.
fn decode_location_filter(bytes: &[u8]) -> Value {
    const NAMES: [&str; 4] = ["start_group", "start_object", "end_group_delta", "end_object"];
    let fields = crate::draft20::message::decode_location_filter(bytes)
        .expect("the decoder accepted this parameter, so its value parses");
    let mut obj = Map::new();
    if fields.is_empty() {
        obj.insert("removed".into(), Value::Bool(true));
        return Value::Map(obj);
    }
    for (name, value) in NAMES.iter().zip(fields) {
        obj.insert((*name).to_string(), vi(value));
    }
    Value::Map(obj)
}

/// Decode a draft-20 FILL_PARAMETERS value: a nested parameter block in its own
/// scope, reported the same way an outer block is.
///
/// The nesting is what makes this recursive with [`params_to_json`] — a fill's
/// LOCATION_FILTER is rendered exactly as the subscription's is — and it
/// bottoms out because Table 6 does not list FILL_PARAMETERS inside itself.
fn decode_fill_parameters(bytes: &[u8]) -> Value {
    let nested = crate::draft20::message::decode_fill_parameters(bytes)
        .expect("the decoder accepted this parameter, so its value parses");
    params_to_json(&nested)
}

fn auth_token_to_json_d20(bytes: &[u8]) -> Value {
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
            // Draft-18 onwards: token_value runs to end of bytes (no inner
            // length).
            o.insert("token_value".into(), Value::Bytes(buf.to_vec()));
        }
        _ => {
            if let Ok(tt) = VarInt::decode_moqt::<Wire>(&mut buf) {
                o.insert("token_type".into(), vi(tt.into_inner()));
            }
            o.insert("token_value".into(), Value::Bytes(buf.to_vec()));
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

fn decode_track_namespace_prefix(bytes: &[u8]) -> Value {
    let mut buf = bytes;
    match TrackNamespace::decode_allow_empty_moqt::<Wire>(&mut buf) {
        Ok(ns) => ns_to_json(&ns),
        Err(_) => Value::Bytes(bytes.to_vec()),
    }
}

fn params_to_json(params: &[KeyValuePair]) -> Value {
    let mut obj = Map::new();
    let mut unknown = Vec::new();

    for p in params {
        let key = p.key.into_inner();
        if let Some(name) = d20_param_name(key) {
            match (&p.value, key) {
                (KvpValue::Bytes(b), 0x21) => {
                    obj.insert(name.to_string(), decode_location_filter(b));
                }
                (KvpValue::Bytes(b), 0x23) => {
                    obj.insert(name.to_string(), decode_fill_parameters(b));
                }
                // One arm for all five: which of them carries a Property Type
                // is a property of the type, and `range_filter` is the one
                // place that decides it. Two arms passing a bool were two
                // chances to answer it differently.
                (KvpValue::Bytes(b), 0x25..=0x29) => {
                    obj.insert(name.to_string(), decode_range_filter(b, key));
                }
                (KvpValue::Bytes(b), 0x09) => {
                    obj.insert(name.to_string(), decode_largest_object(b));
                }
                (KvpValue::Bytes(b), 0x34) => {
                    obj.insert(name.to_string(), decode_track_namespace_prefix(b));
                }
                (KvpValue::Bytes(b), _) if name == "authorization_token" => {
                    obj.insert(name.to_string(), auth_token_to_json_d20(b));
                }
                (KvpValue::Varint(v), _) => {
                    obj.insert(name.to_string(), vi(v.into_inner()));
                }
                (KvpValue::Bytes(b), _) => {
                    obj.insert(
                        name.to_string(),
                        Value::Text(String::from_utf8_lossy(b).into_owned()),
                    );
                }
            }
        } else {
            let mut entry = Map::new();
            entry.insert("id".to_string(), Value::Text(format!("0x{:x}", key)));
            match &p.value {
                KvpValue::Varint(v) => {
                    entry.insert("length".to_string(), vi(v.into_inner()));
                }
                KvpValue::Bytes(b) => {
                    entry.insert("length".to_string(), vi(b.len() as u64));
                    entry.insert("raw_hex".to_string(), Value::Bytes(b.to_vec()));
                }
            }
            unknown.push(Value::Map(entry));
        }
    }

    if !unknown.is_empty() {
        obj.insert("unknown".to_string(), Value::Array(unknown));
    }

    Value::Map(obj)
}

fn options_to_json(options: &[KeyValuePair]) -> Value {
    let mut obj = Map::new();
    for p in options {
        let key = p.key.into_inner();
        if let Some(name) = d20_option_name(key) {
            match &p.value {
                KvpValue::Varint(v) => {
                    obj.insert(name.to_string(), vi(v.into_inner()));
                }
                KvpValue::Bytes(b) if name == "authorization_token" => {
                    obj.insert(name.to_string(), auth_token_to_json_d20(b));
                }
                KvpValue::Bytes(b) => {
                    obj.insert(
                        name.to_string(),
                        Value::Text(String::from_utf8_lossy(b).into_owned()),
                    );
                }
            }
        }
    }
    Value::Map(obj)
}

fn d20_track_prop_name(key: u64) -> Option<&'static str> {
    match key {
        0x02 => Some("object_delivery_timeout"),
        0x04 => Some("max_cache_duration"),
        0x06 => Some("subgroup_delivery_timeout"),
        0x0b => Some("immutable_properties"),
        0x0e => Some("default_publisher_priority"),
        0x22 => Some("default_publisher_group_order"),
        0x30 => Some("dynamic_groups"),
        _ => None,
    }
}

fn track_props_to_json(props: &[KeyValuePair]) -> Value {
    let mut obj = Map::new();
    for p in props {
        let key = p.key.into_inner();
        let name = d20_track_prop_name(key)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("0x{:x}", key));
        match &p.value {
            KvpValue::Varint(v) => {
                obj.insert(name, vi(v.into_inner()));
            }
            KvpValue::Bytes(b) => {
                obj.insert(name, Value::Bytes(b.to_vec()));
            }
        }
    }
    Value::Map(obj)
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
            o.insert("track_properties".into(), track_props_to_json(&m.track_properties));
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
            if let Some(r) = &m.redirect {
                let mut r_obj = Map::new();
                r_obj.insert(
                    "connect_uri".into(),
                    Value::Text(String::from_utf8_lossy(&r.connect_uri).into_owned()),
                );
                r_obj.insert("track_namespace".into(), ns_to_json(&r.track_namespace));
                r_obj.insert(
                    "track_name".into(),
                    Value::Text(String::from_utf8_lossy(&r.track_name).into_owned()),
                );
                o.insert("redirect".into(), Value::Map(r_obj));
            }
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
            o.insert("parameters".into(), params_to_json(&m.parameters));
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
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o.insert("track_properties".into(), track_props_to_json(&m.track_properties));
            o
        }
        // New in draft-20, and the only control message with a Parameters field
        // and nothing else: no Request ID, no Track Properties.
        ControlMessage::PublishStateNotify(m) => {
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
            o.insert("namespace_prefix".into(), ns_to_json(&m.namespace_prefix));
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o
        }
        ControlMessage::SubscribeTracks(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("namespace_prefix".into(), ns_to_json(&m.namespace_prefix));
            o.insert("parameters".into(), params_to_json(&m.parameters));
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
            o.insert("parameters".into(), params_to_json(&m.parameters));
            o
        }
        // Draft-20's FETCH is byte-identical to SUBSCRIBE apart from its type
        // code: no Fetch Type, no joining pair, no inline range.
        ControlMessage::Fetch(m) => {
            let mut o = Map::new();
            o.insert("request_id".into(), vi(m.request_id.into_inner()));
            o.insert("track_namespace".into(), ns_to_json(&m.track_namespace));
            o.insert(
                "track_name".into(),
                Value::Text(String::from_utf8_lossy(&m.track_name).into_owned()),
            );
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
        ControlMessage::PublishSkipped(m) => {
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

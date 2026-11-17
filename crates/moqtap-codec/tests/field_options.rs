#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
    feature = "draft23"
))]

//! `fields_with` under `Opaque::Bytes`, on every compiled draft: opaque fields
//! are `Bytes`, text fields are `Text` only when they are UTF-8, and a Range
//! Filter's `violates` is a code.
//!
//! Each message starts from a vector in the corpus and has its fields replaced.

mod test_vectors;

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::fields::{FieldMap, FieldOptions, FieldValue, Opaque};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::{Moqt18, VarInt};
use moqtap_codec::version::DraftVersion;
use test_vectors::{load_vectors, vectors_dir};

const EXACT: FieldOptions = FieldOptions::new().with_opaque(Opaque::Bytes);

macro_rules! drafts {
    ($( $feat:literal => $variant:ident, $module:ident, $reason:ident, $setup:ident . $list:ident; )+) => {
        fn compiled(draft: DraftVersion) -> bool {
            match draft {
                $( DraftVersion::$variant => cfg!(feature = $feat), )+
            }
        }

        fn set_track(msg: &mut AnyControlMessage, ns: TrackNamespace, name: &[u8]) {
            match msg {
                $(
                    #[cfg(feature = $feat)]
                    AnyControlMessage::$variant(
                        moqtap_codec::$module::message::ControlMessage::Subscribe(m),
                    ) => {
                        m.track_namespace = ns;
                        m.track_name = name.to_vec();
                    }
                )+
                other => panic!("not a SUBSCRIBE: {other:?}"),
            }
        }

        fn set_parameters(msg: &mut AnyControlMessage, parameters: Vec<KeyValuePair>) {
            match msg {
                $(
                    #[cfg(feature = $feat)]
                    AnyControlMessage::$variant(
                        moqtap_codec::$module::message::ControlMessage::Subscribe(m),
                    ) => m.parameters = parameters,
                )+
                other => panic!("not a SUBSCRIBE: {other:?}"),
            }
        }

        fn set_new_session_uri(msg: &mut AnyControlMessage, uri: &[u8]) {
            match msg {
                $(
                    #[cfg(feature = $feat)]
                    AnyControlMessage::$variant(
                        moqtap_codec::$module::message::ControlMessage::GoAway(m),
                    ) => m.new_session_uri = uri.to_vec(),
                )+
                other => panic!("not a GOAWAY: {other:?}"),
            }
        }

        fn set_reason(msg: &mut AnyControlMessage, reason: &[u8]) {
            match msg {
                $(
                    #[cfg(feature = $feat)]
                    AnyControlMessage::$variant(
                        moqtap_codec::$module::message::ControlMessage::$reason(m),
                    ) => m.reason_phrase = reason.to_vec(),
                )+
                other => panic!("not a message with a reason phrase: {other:?}"),
            }
        }

        fn set_setup(msg: &mut AnyControlMessage, list: Vec<KeyValuePair>) {
            match msg {
                $(
                    #[cfg(feature = $feat)]
                    AnyControlMessage::$variant(
                        moqtap_codec::$module::message::ControlMessage::$setup(m),
                    ) => m.$list = list,
                )+
                other => panic!("not a SETUP: {other:?}"),
            }
        }
    };
}

drafts! {
    "draft07" => Draft07, draft07, SubscribeError, ClientSetup.parameters;
    "draft08" => Draft08, draft08, SubscribeError, ClientSetup.parameters;
    "draft09" => Draft09, draft09, SubscribeError, ClientSetup.parameters;
    "draft10" => Draft10, draft10, SubscribeError, ClientSetup.parameters;
    "draft11" => Draft11, draft11, SubscribeError, ClientSetup.parameters;
    "draft12" => Draft12, draft12, SubscribeError, ClientSetup.parameters;
    "draft13" => Draft13, draft13, SubscribeError, ClientSetup.parameters;
    "draft14" => Draft14, draft14, SubscribeError, ClientSetup.parameters;
    "draft15" => Draft15, draft15, RequestError, ClientSetup.parameters;
    "draft16" => Draft16, draft16, RequestError, ClientSetup.parameters;
    "draft17" => Draft17, draft17, RequestError, Setup.options;
    "draft18" => Draft18, draft18, RequestError, Setup.options;
    "draft19" => Draft19, draft19, RequestError, Setup.options;
    "draft20" => Draft20, draft20, RequestError, Setup.options;
    "draft21" => Draft21, draft21, RequestError, Setup.options;
    "draft22" => Draft22, draft22, RequestError, Setup.options;
    "draft23" => Draft23, draft23, RequestError, Setup.options;
}

fn compiled_drafts() -> impl Iterator<Item = DraftVersion> {
    DraftVersion::ALL.into_iter().filter(|d| compiled(*d))
}

fn in_range(draft: DraftVersion, first: u8, last: u8) -> bool {
    (first..=last).contains(&draft.number())
}

/// The first decodable vector in `file` of `draft`'s corpus.
fn template(draft: DraftVersion, file: &str) -> AnyControlMessage {
    let path =
        vectors_dir().join(format!("transport/draft{:02}/codec/messages/{file}", draft.number()));
    load_vectors(&path)
        .vectors
        .iter()
        .filter(|v| v.decoded.is_some())
        .find_map(|v| {
            let bytes = hex::decode(&v.hex).ok()?;
            AnyControlMessage::decode(draft, &mut &bytes[..]).ok()
        })
        .unwrap_or_else(|| panic!("{draft:?}: no decodable vector in {file}"))
}

fn reason_template(draft: DraftVersion) -> AnyControlMessage {
    template(
        draft,
        if draft.number() <= 14 { "subscribe-error.json" } else { "request-error.json" },
    )
}

fn setup_template(draft: DraftVersion) -> AnyControlMessage {
    template(draft, if draft.number() <= 16 { "client-setup.json" } else { "setup.json" })
}

fn pair(key: u64, value: KvpValue) -> KeyValuePair {
    KeyValuePair { key: VarInt::from_u64(key).expect("a key"), value }
}

fn bytes(key: u64, value: &[u8]) -> KeyValuePair {
    pair(key, KvpValue::Bytes(value.to_vec()))
}

fn moqt(value: u64, out: &mut Vec<u8>) {
    VarInt::from_u64(value).expect("a varint").encode_moqt::<Moqt18>(out);
}

fn get<'a>(map: &'a FieldMap, key: &str) -> &'a FieldValue {
    map.get(key).unwrap_or_else(|| panic!("no `{key}` in {map:?}"))
}

fn as_map(value: &FieldValue) -> &FieldMap {
    match value {
        FieldValue::Map(m) => m,
        other => panic!("not a map: {other:?}"),
    }
}

fn as_array(value: &FieldValue) -> &[FieldValue] {
    match value {
        FieldValue::Array(items) => items,
        other => panic!("not an array: {other:?}"),
    }
}

/// The single entry of the parameter list under `key`.
fn only_entry<'a>(map: &'a FieldMap, key: &str) -> &'a FieldMap {
    let items = as_array(get(map, key));
    assert_eq!(items.len(), 1, "one entry under `{key}`: {items:?}");
    as_map(&items[0])
}

fn text(s: &str) -> FieldValue {
    FieldValue::Text(s.into())
}

fn raw(b: &[u8]) -> FieldValue {
    FieldValue::Bytes(b.to_vec())
}

#[test]
fn namespace_elements_and_track_names_are_bytes() {
    for draft in compiled_drafts() {
        let mut msg = template(draft, "subscribe.json");
        set_track(&mut msg, TrackNamespace(vec![b"ok".to_vec(), b"a\xff".to_vec()]), b"t\xfe");

        let exact = msg.fields_with(EXACT);
        assert_eq!(
            as_array(get(&exact, "track_namespace")),
            [raw(b"ok"), raw(b"a\xff")],
            "{draft:?}"
        );
        assert_eq!(get(&exact, "track_name"), &raw(b"t\xfe"), "{draft:?}");

        let lossy = msg.fields();
        assert_eq!(
            as_array(get(&lossy, "track_namespace")),
            [text("ok"), text("a\u{FFFD}")],
            "{draft:?}"
        );
        assert_eq!(get(&lossy, "track_name"), &text("t\u{FFFD}"), "{draft:?}");
    }
}

#[test]
fn a_reason_phrase_is_bytes_before_draft_11_and_utf8_text_from_it() {
    for draft in compiled_drafts() {
        let mut msg = reason_template(draft);
        set_reason(&mut msg, b"bye");
        let exact = msg.fields_with(EXACT);
        let expected = if draft.number() <= 10 { raw(b"bye") } else { text("bye") };
        assert_eq!(get(&exact, "reason_phrase"), &expected, "{draft:?}");

        set_reason(&mut msg, b"\xc3");
        assert_eq!(get(&msg.fields_with(EXACT), "reason_phrase"), &raw(b"\xc3"), "{draft:?}");
        assert_eq!(get(&msg.fields(), "reason_phrase"), &text("\u{FFFD}"), "{draft:?}");
    }
}

#[test]
fn a_new_session_uri_is_text_only_when_it_is_utf8() {
    for draft in compiled_drafts() {
        let mut msg = template(draft, "goaway.json");
        set_new_session_uri(&mut msg, b"moqt://a");
        assert_eq!(get(&msg.fields_with(EXACT), "new_session_uri"), &text("moqt://a"), "{draft:?}");
        set_new_session_uri(&mut msg, b"\xff");
        assert_eq!(get(&msg.fields_with(EXACT), "new_session_uri"), &raw(b"\xff"), "{draft:?}");
        assert_eq!(get(&msg.fields(), "new_session_uri"), &text("\u{FFFD}"), "{draft:?}");
    }
}

/// The setup parameters whose value is text, by type, with the name each
/// draft gives it.
fn text_setup_parameters(draft: DraftVersion) -> Vec<(u64, &'static str)> {
    let mut out = vec![(0x01, "path")];
    if draft.number() >= 14 {
        out.push((0x05, "authority"));
    }
    if draft.number() >= 15 {
        out.push((0x07, "moqt_implementation"));
    }
    out
}

#[test]
fn text_setup_parameters_are_text_only_when_they_are_utf8() {
    for draft in compiled_drafts() {
        let list_key = if draft.number() <= 16 { "parameters" } else { "options" };
        for (key, name) in text_setup_parameters(draft) {
            let mut msg = setup_template(draft);
            for (value, expected) in [(&b"p"[..], text("p")), (&b"\xff"[..], raw(b"\xff"))] {
                set_setup(&mut msg, vec![bytes(key, value)]);
                let exact = msg.fields_with(EXACT);
                let entry = only_entry(&exact, list_key);
                assert_eq!(get(entry, "type"), &text(&format!("0x{key:x}")), "{draft:?} {name}");
                assert_eq!(get(entry, "name"), &text(name), "{draft:?}");
                assert_eq!(get(entry, "value"), &expected, "{draft:?} {name}");
            }
            let lossy = msg.fields();
            assert_eq!(get(only_entry(&lossy, list_key), "value"), &text("\u{FFFD}"), "{draft:?}");
        }
    }
}

#[test]
fn authorization_info_is_text_only_when_it_is_utf8() {
    for draft in compiled_drafts().filter(|d| in_range(*d, 7, 10)) {
        let mut msg = template(draft, "subscribe.json");
        for (value, expected) in [(&b"tok"[..], text("tok")), (&b"\xff"[..], raw(b"\xff"))] {
            set_parameters(&mut msg, vec![bytes(0x02, value)]);
            let exact = msg.fields_with(EXACT);
            let entry = only_entry(&exact, "parameters");
            assert_eq!(get(entry, "name"), &text("authorization_info"), "{draft:?}");
            assert_eq!(get(entry, "value"), &expected, "{draft:?}");
        }
    }
}

#[test]
fn an_unnamed_parameter_keeps_its_raw_bytes_under_both_options() {
    for draft in compiled_drafts() {
        let mut msg = template(draft, "subscribe.json");
        set_parameters(&mut msg, vec![bytes(0x7d, b"\xff")]);
        for options in [FieldOptions::default(), EXACT] {
            let rendered = msg.fields_with(options);
            let entry = only_entry(&rendered, "parameters");
            assert_eq!(get(entry, "type"), &text("0x7d"), "{draft:?}");
            assert_eq!(entry.get("name"), None, "{draft:?}");
            assert_eq!(get(entry, "raw_hex"), &raw(b"\xff"), "{draft:?}");
        }
    }
}

/// A REQUEST_ERROR carrying a redirect to `uri`, on drafts 18 through 23.
#[allow(unused_variables, unreachable_code)]
fn redirect(draft: DraftVersion, uri: &[u8]) -> AnyControlMessage {
    let mut msg = template(draft, "request-error.json");
    let ns = TrackNamespace(vec![b"n\xff".to_vec()]);
    let name = b"t\xfe".to_vec();
    macro_rules! redirect {
        ($( $feat:literal => $variant:ident, $module:ident; )+) => {
            match &mut msg {
                $(
                    #[cfg(feature = $feat)]
                    AnyControlMessage::$variant(
                        moqtap_codec::$module::message::ControlMessage::RequestError(m),
                    ) => {
                        m.redirect = Some(moqtap_codec::$module::message::Redirect {
                            connect_uri: uri.to_vec(),
                            track_namespace: ns,
                            track_name: name,
                        });
                    }
                )+
                #[cfg(feature = "draft23")]
                AnyControlMessage::Draft23(
                    moqtap_codec::draft23::message::ControlMessage::RequestError(m),
                ) => {
                    let detail = moqtap_codec::draft23::message::Redirect {
                        connect_uri: uri.to_vec(),
                        track_namespace: ns,
                        track_name: name,
                    }
                    .to_error_detail()
                    .expect("a redirect encodes");
                    m.error_details = vec![detail];
                }
                other => panic!("no redirect on {other:?}"),
            }
        };
    }
    redirect! {
        "draft18" => Draft18, draft18;
        "draft19" => Draft19, draft19;
        "draft20" => Draft20, draft20;
        "draft21" => Draft21, draft21;
        "draft22" => Draft22, draft22;
    }
    msg
}

/// The redirect map: `redirect` on drafts 18 through 22, the `redirect` Error
/// Detail on draft-23.
fn redirect_map(draft: DraftVersion, fields: &FieldMap) -> FieldMap {
    if draft == DraftVersion::Draft23 {
        let entry = only_entry(fields, "error_details");
        assert_eq!(get(entry, "name"), &text("redirect"));
        as_map(get(entry, "value")).clone()
    } else {
        as_map(get(fields, "redirect")).clone()
    }
}

#[test]
fn a_connect_uri_is_text_only_when_it_is_utf8_and_its_track_is_bytes() {
    for draft in compiled_drafts().filter(|d| in_range(*d, 18, 23)) {
        let exact = redirect_map(draft, &redirect(draft, b"moqt://b").fields_with(EXACT));
        assert_eq!(get(&exact, "connect_uri"), &text("moqt://b"), "{draft:?}");
        assert_eq!(as_array(get(&exact, "track_namespace")), [raw(b"n\xff")], "{draft:?}");
        assert_eq!(get(&exact, "track_name"), &raw(b"t\xfe"), "{draft:?}");

        let msg = redirect(draft, b"\xff");
        let exact = redirect_map(draft, &msg.fields_with(EXACT));
        assert_eq!(get(&exact, "connect_uri"), &raw(b"\xff"), "{draft:?}");
        let lossy = redirect_map(draft, &msg.fields());
        assert_eq!(get(&lossy, "connect_uri"), &text("\u{FFFD}"), "{draft:?}");
    }
}

#[test]
fn a_track_namespace_prefix_is_bytes() {
    for draft in compiled_drafts().filter(|d| in_range(*d, 18, 23)) {
        let mut value = Vec::new();
        TrackNamespace(vec![b"p".to_vec(), b"\xff".to_vec()]).encode_moqt::<Moqt18>(&mut value);
        let mut msg = template(draft, "subscribe.json");
        set_parameters(&mut msg, vec![bytes(0x34, &value)]);
        let exact = msg.fields_with(EXACT);
        let entry = only_entry(&exact, "parameters");
        assert_eq!(get(entry, "name"), &text("track_namespace_prefix"), "{draft:?}");
        assert_eq!(as_array(get(entry, "value")), [raw(b"p"), raw(b"\xff")], "{draft:?}");
    }
}

/// PRIORITY_FILTER 200-300 in SetID 0.
fn priority_above_the_field() -> Vec<u8> {
    let mut value = vec![0x00];
    moqt(200, &mut value);
    moqt(100, &mut value);
    value
}

/// OBJECT_PROPERTY_FILTER over Property Type 1, range 0-5, in SetID 0.
fn odd_property_type() -> Vec<u8> {
    let mut value = vec![0x00];
    moqt(1, &mut value);
    moqt(0, &mut value);
    moqt(5, &mut value);
    value
}

/// FILL_PARAMETERS holding one parameter.
fn fill_parameters(key: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    moqt(1, &mut out);
    moqt(key, &mut out);
    moqt(value.len() as u64, &mut out);
    out.extend_from_slice(value);
    out
}

fn violates(entry: &FieldMap) -> &FieldValue {
    get(as_map(get(entry, "value")), "violates")
}

#[test]
fn a_broken_range_filter_names_its_rule_by_code() {
    for draft in compiled_drafts().filter(|d| in_range(*d, 19, 23)) {
        for (key, value, code) in [
            (0x27, priority_above_the_field(), "priority_above_the_field"),
            (0x28, odd_property_type(), "property_type_is_not_an_integer"),
        ] {
            let mut msg = template(draft, "subscribe.json");
            set_parameters(&mut msg, vec![bytes(key, &value)]);
            let exact = msg.fields_with(EXACT);
            assert_eq!(violates(only_entry(&exact, "parameters")), &text(code), "{draft:?}");
            let lossy = msg.fields();
            let FieldValue::Text(display) = violates(only_entry(&lossy, "parameters")) else {
                panic!("{draft:?}: `violates` is text");
            };
            assert_ne!(display, code, "{draft:?}: fields() keeps the description");
        }
    }
}

#[test]
fn a_broken_range_filter_inside_fill_parameters_names_its_rule_by_code() {
    for draft in compiled_drafts().filter(|d| in_range(*d, 20, 23)) {
        let mut msg = template(draft, "subscribe.json");
        let fill = fill_parameters(0x27, &priority_above_the_field());
        set_parameters(&mut msg, vec![bytes(0x23, &fill)]);
        let exact = msg.fields_with(EXACT);
        let outer = only_entry(&exact, "parameters");
        assert_eq!(get(outer, "name"), &text("fill_parameters"), "{draft:?}");
        let nested = as_array(get(outer, "value"));
        assert_eq!(nested.len(), 1, "{draft:?}");
        assert_eq!(violates(as_map(&nested[0])), &text("priority_above_the_field"), "{draft:?}");
    }
}

#[test]
fn new_options_are_the_default_ones() {
    assert_eq!(FieldOptions::new(), FieldOptions::default());
    assert_eq!(EXACT.opaque, Opaque::Bytes);
}

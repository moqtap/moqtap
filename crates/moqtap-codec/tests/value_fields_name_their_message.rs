//! A Forward or Content Exists field outside 0 and 1 is refused with the message
//! it was in.
//!
//! Each message states the rule in its own section. draft-14 Section 9.7
//! (SUBSCRIBE): "Forward: If 1, Objects matching the subscription are forwarded
//! to the subscriber. If 0, Objects are not forwarded to the subscriber. Any
//! other value is a protocol error and MUST terminate the session with a
//! PROTOCOL_VIOLATION (Section 3.4)." draft-14 Section 9.13 (PUBLISH): "Any
//! value other than 0 or 1 is a PROTOCOL_VIOLATION." draft-07 Section 6.15
//! (SUBSCRIBE_OK) and draft-07 Section 6.19 (SUBSCRIBE_DONE) state it of
//! ContentExists. Each decode site is driven under its own message type.
//!
//! Every frame starts as a valid vector from the corpus. The test decodes it,
//! sets the field through the struct, re-encodes it, and then rewrites the one
//! byte that is the field. Everything else in the frame is the encoder's.

#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14"
))]

use serde_json::Value;
use std::path::Path;

/// The first vector of `file` in `draft`'s message corpus that carries no
/// expected error.
fn valid_frame(draft: &str, file: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors/transport")
        .join(draft)
        .join("codec/messages")
        .join(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let json: Value = serde_json::from_str(&text).expect("a vector file is JSON");
    let vector = json["vectors"]
        .as_array()
        .expect("a vector file has vectors")
        .iter()
        .find(|v| v.get("error").is_none_or(Value::is_null))
        .unwrap_or_else(|| panic!("{} has no valid vector", path.display()));
    hex::decode(vector["hex"].as_str().expect("a vector has hex")).expect("the hex decodes")
}

/// The one position where `a` and `b` differ.
#[allow(dead_code)]
fn the_one_difference(a: &[u8], b: &[u8]) -> usize {
    assert_eq!(a.len(), b.len(), "the two encodings differ in length");
    let at: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
    assert_eq!(at.len(), 1, "the two encodings differ in {at:?}, not in one byte");
    at[0]
}

/// The position of the byte just before the unique `[0x2A, 0x2B]` in `frame`,
/// which is where a Content Exists field sits ahead of a Largest Location of
/// {42, 43}.
#[allow(dead_code)]
fn before_the_marker(frame: &[u8]) -> usize {
    let at: Vec<usize> =
        (1..frame.len().saturating_sub(1)).filter(|&i| frame[i..i + 2] == [0x2A, 0x2B]).collect();
    assert_eq!(at.len(), 1, "the marker {{42, 43}} is not unique in {frame:02x?}");
    assert_eq!(frame[at[0] - 1], 0x01, "the byte before the marker is not Content Exists 1");
    at[0] - 1
}

macro_rules! draft_module {
    ($module:ident, $dir:literal, content: [$($ce:tt)*]) => {
        draft_module!(@body $module, $dir, {}, { $($ce)* });
    };
    ($module:ident, $dir:literal, forward: [$($fwd:tt)*], content: [$($ce:tt)*]) => {
        draft_module!(@body $module, $dir, {
            #[test]
            fn a_forward_field_is_refused_with_its_message() {
                $($fwd)*
            }
        }, { $($ce)* });
    };
    (@body $module:ident, $dir:literal, { $($forward_test:tt)* }, { $($ce:tt)* }) => {
        #[cfg(feature = $dir)]
        mod $module {
            #[allow(unused_imports)]
            use super::{before_the_marker, the_one_difference, valid_frame};
            use moqtap_codec::$module::message::*;
            use moqtap_codec::error::CodecError;
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            #[allow(unused_imports)]
            use moqtap_codec::varint::VarInt;

            fn decode(frame: &[u8]) -> Result<ControlMessage, CodecError> {
                ControlMessage::decode(&mut &frame[..])
            }

            fn encode(message: &ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                message.encode(&mut out).expect("the encoder writes the fixture");
                out
            }

            #[allow(dead_code)]
            fn vi(v: u64) -> VarInt {
                VarInt::from_u64(v).expect("fixture value fits a varint")
            }

            $($forward_test)*

            #[test]
            fn a_content_exists_field_is_refused_with_its_message() {
                $($ce)*
            }
        }
    };
}

/// Drive one Forward site: `$file`'s vector as `$variant`, refused with that message type.
#[allow(unused_macros)]
macro_rules! forward_site {
    ($draft:literal, $file:literal, $variant:ident) => {{
        let mut message = decode(&valid_frame($draft, $file)).expect("the vector decodes");
        let ControlMessage::$variant(m) = &mut message else {
            panic!("{} is not a {}", $file, stringify!($variant))
        };
        m.forward = Forward::Forward;
        let on = encode(&message);
        let ControlMessage::$variant(m) = &mut message else { unreachable!() };
        m.forward = Forward::DontForward;
        let off = encode(&message);
        let mut bad = on.clone();
        bad[the_one_difference(&on, &off)] = 2;
        assert_eq!(
            decode(&bad),
            Err(CodecError::InvalidForward { value: 2, message_type: MessageType::$variant.id() }),
            "{}",
            stringify!($variant)
        );
    }};
}

/// Drive one Content Exists site whose Largest Location is a `Location`.
#[allow(unused_macros)]
macro_rules! content_site_location {
    ($draft:literal, $file:literal, $variant:ident) => {{
        let mut message = decode(&valid_frame($draft, $file)).expect("the vector decodes");
        let ControlMessage::$variant(m) = &mut message else {
            panic!("{} is not a {}", $file, stringify!($variant))
        };
        m.content_exists = ContentExists::HasLargestLocation;
        m.largest_location = Some(Location { group: vi(42), object: vi(43) });
        let mut bad = encode(&message);
        let at = before_the_marker(&bad);
        bad[at] = 2;
        assert_eq!(
            decode(&bad),
            Err(CodecError::InvalidContentExists {
                value: 2,
                message_type: MessageType::$variant.id(),
            }),
            "{}",
            stringify!($variant)
        );
    }};
}

/// Drive one ContentExists site whose two ids are separate fields.
#[allow(unused_macros)]
macro_rules! content_site_ids {
    ($draft:literal, $file:literal, $variant:ident, $group:ident, $object:ident) => {{
        let mut message = decode(&valid_frame($draft, $file)).expect("the vector decodes");
        let ControlMessage::$variant(m) = &mut message else {
            panic!("{} is not a {}", $file, stringify!($variant))
        };
        m.content_exists = ContentExists::HasLargestLocation;
        m.$group = Some(vi(42));
        m.$object = Some(vi(43));
        let mut bad = encode(&message);
        let at = before_the_marker(&bad);
        bad[at] = 2;
        assert_eq!(
            decode(&bad),
            Err(CodecError::InvalidContentExists {
                value: 2,
                message_type: MessageType::$variant.id(),
            }),
            "{}",
            stringify!($variant)
        );
    }};
}

draft_module!(draft07, "draft07", content: [
    content_site_ids!("draft07", "subscribe-ok.json", SubscribeOk, largest_group_id, largest_object_id);
    content_site_ids!("draft07", "subscribe-done.json", SubscribeDone, final_group, final_object);
]);
draft_module!(draft08, "draft08", content: [
    content_site_ids!("draft08", "subscribe-ok.json", SubscribeOk, largest_group_id, largest_object_id);
]);
draft_module!(draft09, "draft09", content: [
    content_site_ids!("draft09", "subscribe-ok.json", SubscribeOk, largest_group_id, largest_object_id);
]);
draft_module!(draft10, "draft10", content: [
    content_site_ids!("draft10", "subscribe-ok.json", SubscribeOk, largest_group_id, largest_object_id);
]);
draft_module!(draft11, "draft11", forward: [
    forward_site!("draft11", "subscribe.json", Subscribe);
    forward_site!("draft11", "subscribe-update.json", SubscribeUpdate);
], content: [
    content_site_location!("draft11", "subscribe-ok.json", SubscribeOk);
]);
draft_module!(draft12, "draft12", forward: [
    forward_site!("draft12", "subscribe.json", Subscribe);
    forward_site!("draft12", "subscribe-update.json", SubscribeUpdate);
    forward_site!("draft12", "publish.json", Publish);
    forward_site!("draft12", "publish-ok.json", PublishOk);
], content: [
    content_site_location!("draft12", "subscribe-ok.json", SubscribeOk);
    content_site_location!("draft12", "publish.json", Publish);
]);
draft_module!(draft13, "draft13", forward: [
    forward_site!("draft13", "subscribe.json", Subscribe);
    forward_site!("draft13", "subscribe-update.json", SubscribeUpdate);
    forward_site!("draft13", "publish.json", Publish);
    forward_site!("draft13", "publish-ok.json", PublishOk);
    forward_site!("draft13", "track-status.json", TrackStatus);
], content: [
    content_site_location!("draft13", "subscribe-ok.json", SubscribeOk);
    content_site_location!("draft13", "publish.json", Publish);
    content_site_location!("draft13", "track-status-ok.json", TrackStatusOk);
]);
draft_module!(draft14, "draft14", forward: [
    forward_site!("draft14", "subscribe.json", Subscribe);
    forward_site!("draft14", "subscribe-update.json", SubscribeUpdate);
    forward_site!("draft14", "publish.json", Publish);
    forward_site!("draft14", "publish-ok.json", PublishOk);
    forward_site!("draft14", "track-status.json", TrackStatus);
], content: [
    content_site_location!("draft14", "subscribe-ok.json", SubscribeOk);
    content_site_location!("draft14", "publish.json", Publish);
    content_site_location!("draft14", "track-status-ok.json", TrackStatusOk);
]);

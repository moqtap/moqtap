use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader};
use moqtap_codec::draft14::data_stream::{DatagramObject, DatagramType};
use moqtap_codec::draft14::message::{ControlMessage, GoAway};
use moqtap_codec::varint::VarInt;

use moqtap_proxy::event::{ProxySide, SessionId};
use moqtap_proxy::hook::*;

// ============================================================
// NoOpHook
// ============================================================

#[test]
fn noop_hook_returns_none_for_control() {
    let hook = NoOpHook;
    let msg =
        AnyControlMessage::Draft14(ControlMessage::GoAway(GoAway { new_session_uri: vec![] }));
    let raw = b"some raw bytes";
    let result = hook.on_control_message(SessionId(1), ProxySide::ClientToProxy, &msg, raw);
    assert!(result.is_none());
}

#[test]
fn noop_hook_returns_none_for_datagram() {
    let hook = NoOpHook;
    let header = AnyDatagramHeader::Draft14(DatagramObject {
        datagram_type: DatagramType::from_u8(0x00).unwrap(),
        track_alias: VarInt::from_u64(1).unwrap(),
        group_id: VarInt::from_u64(0).unwrap(),
        object_id: VarInt::from_u64(0).unwrap(),
        publisher_priority: 128,
        extension_headers: Vec::new(),
        status: None,
        payload: Vec::new(),
    });
    let raw = b"datagram bytes";
    let result = hook.on_datagram(SessionId(1), ProxySide::RelayToProxy, &header, raw);
    assert!(result.is_none());
}

// ============================================================
// Custom hook that mutates
// ============================================================

struct MutatingHook;

impl ProxyHook for MutatingHook {
    fn wants_control_mutation(&self) -> bool {
        true
    }

    fn on_control_message(
        &self,
        _session_id: SessionId,
        _side: ProxySide,
        _message: &AnyControlMessage,
        _raw_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        Some(b"replaced control".to_vec())
    }

    fn on_datagram(
        &self,
        _session_id: SessionId,
        _side: ProxySide,
        _header: &AnyDatagramHeader,
        _raw_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        Some(b"replaced datagram".to_vec())
    }
}

#[test]
fn mutating_hook_replaces_control() {
    let hook = MutatingHook;
    let msg =
        AnyControlMessage::Draft14(ControlMessage::GoAway(GoAway { new_session_uri: vec![] }));
    let result = hook.on_control_message(SessionId(1), ProxySide::ClientToProxy, &msg, b"original");
    assert_eq!(result.unwrap(), b"replaced control");
}

#[test]
fn mutating_hook_replaces_datagram() {
    let hook = MutatingHook;
    let header = AnyDatagramHeader::Draft14(DatagramObject {
        datagram_type: DatagramType::from_u8(0x00).unwrap(),
        track_alias: VarInt::from_u64(1).unwrap(),
        group_id: VarInt::from_u64(0).unwrap(),
        object_id: VarInt::from_u64(0).unwrap(),
        publisher_priority: 128,
        extension_headers: Vec::new(),
        status: None,
        payload: Vec::new(),
    });
    let result = hook.on_datagram(SessionId(1), ProxySide::RelayToProxy, &header, b"original");
    assert_eq!(result.unwrap(), b"replaced datagram");
}

/// Verify ProxyHook is object-safe.
#[test]
fn hook_is_object_safe() {
    let hook: Box<dyn ProxyHook> = Box::new(NoOpHook);
    let msg =
        AnyControlMessage::Draft14(ControlMessage::GoAway(GoAway { new_session_uri: vec![] }));
    assert!(hook
        .on_control_message(SessionId(1), ProxySide::ClientToProxy, &msg, b"test")
        .is_none());
}

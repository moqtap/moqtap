use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnyObjectHeader, AnySubgroupHeader,
};
use moqtap_codec::draft07::data_stream::ObjectHeader;
use moqtap_codec::draft07::types::ObjectStatus;
use moqtap_codec::draft14::data_stream::{
    DatagramObject, DatagramType, FetchHeader, SubgroupHeader, SubgroupStreamType,
};
use moqtap_codec::draft14::message::{ControlMessage, GoAway};
use moqtap_codec::varint::VarInt;

use moqtap_proxy::event::*;
use moqtap_proxy::observer::*;

// ============================================================
// ProxySide
// ============================================================

#[test]
fn proxy_side_copy_and_eq() {
    let s = ProxySide::ClientToProxy;
    let s2 = s;
    assert_eq!(s, s2);
    assert_ne!(ProxySide::ClientToProxy, ProxySide::RelayToProxy);
    assert_ne!(ProxySide::ProxyToRelay, ProxySide::ProxyToClient);
}

#[test]
fn proxy_side_debug() {
    assert_eq!(format!("{:?}", ProxySide::ClientToProxy), "ClientToProxy");
    assert_eq!(format!("{:?}", ProxySide::ProxyToRelay), "ProxyToRelay");
    assert_eq!(format!("{:?}", ProxySide::RelayToProxy), "RelayToProxy");
    assert_eq!(format!("{:?}", ProxySide::ProxyToClient), "ProxyToClient");
}

// ============================================================
// SessionId
// ============================================================

#[test]
fn session_id_copy_eq_hash() {
    let id1 = SessionId(1);
    let id2 = SessionId(1);
    let id3 = SessionId(2);
    assert_eq!(id1, id2);
    assert_ne!(id1, id3);

    let mut set = HashSet::new();
    set.insert(id1);
    assert!(set.contains(&id2));
    assert!(!set.contains(&id3));
}

// ============================================================
// DataStreamHeaderKind
// ============================================================

#[test]
fn data_stream_header_kind_subgroup() {
    let header = AnySubgroupHeader::Draft14(SubgroupHeader {
        stream_type: SubgroupStreamType::from_u8(0x14).unwrap(),
        track_alias: VarInt::from_u64(1).unwrap(),
        group_id: VarInt::from_u64(0).unwrap(),
        subgroup_id: Some(VarInt::from_u64(0).unwrap()),
        publisher_priority: 128,
    });
    let kind = DataStreamHeaderKind::Subgroup(header);
    let debug = format!("{kind:?}");
    assert!(debug.contains("Subgroup"));
}

#[test]
fn data_stream_header_kind_fetch() {
    let header = AnyFetchHeader::Draft14(FetchHeader { request_id: VarInt::from_u64(2).unwrap() });
    let kind = DataStreamHeaderKind::Fetch(header);
    let debug = format!("{kind:?}");
    assert!(debug.contains("Fetch"));
}

// ============================================================
// ProxyEvent construction
// ============================================================

#[test]
fn proxy_event_session_started() {
    let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let event = ProxyEvent::SessionStarted {
        session_id: SessionId(1),
        client_addr: addr,
        client_transport: "QUIC".into(),
    };
    let debug = format!("{event:?}");
    assert!(debug.contains("SessionStarted"));
}

#[test]
fn proxy_event_control_message() {
    let msg =
        AnyControlMessage::Draft14(ControlMessage::GoAway(GoAway { new_session_uri: vec![] }));
    let event = ProxyEvent::ControlMessage {
        session_id: SessionId(1),
        side: ProxySide::ClientToProxy,
        message: msg,
    };
    let debug = format!("{event:?}");
    assert!(debug.contains("ControlMessage"));
}

#[test]
fn proxy_event_datagram() {
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
    let event = ProxyEvent::Datagram {
        session_id: SessionId(1),
        side: ProxySide::RelayToProxy,
        header,
        payload_len: 42,
    };
    let debug = format!("{event:?}");
    assert!(debug.contains("Datagram"));
}

#[test]
fn proxy_event_object_header() {
    // Draft-14 subgroup objects require stateful per-stream context and are
    // not dispatched via AnyObjectHeader — use draft-07 here to exercise the
    // event's debug formatting.
    let header = AnyObjectHeader::Draft07(ObjectHeader {
        object_id: VarInt::from_u64(0).unwrap(),
        payload_length: VarInt::from_u64(100).unwrap(),
        object_status: ObjectStatus::Normal,
    });
    let event = ProxyEvent::ObjectHeader {
        session_id: SessionId(1),
        side: ProxySide::ProxyToClient,
        header,
    };
    let debug = format!("{event:?}");
    assert!(debug.contains("ObjectHeader"));
}

#[test]
fn proxy_event_stream_events() {
    let bi =
        ProxyEvent::BiStreamOpened { session_id: SessionId(1), side: ProxySide::ClientToProxy };
    let uni =
        ProxyEvent::UniStreamOpened { session_id: SessionId(2), side: ProxySide::RelayToProxy };
    let closed =
        ProxyEvent::StreamClosed { session_id: SessionId(3), side: ProxySide::ProxyToRelay };
    assert!(format!("{bi:?}").contains("BiStreamOpened"));
    assert!(format!("{uni:?}").contains("UniStreamOpened"));
    assert!(format!("{closed:?}").contains("StreamClosed"));
}

#[test]
fn proxy_event_parse_error() {
    let event = ProxyEvent::ParseError {
        session_id: SessionId(1),
        side: ProxySide::ClientToProxy,
        error: "bad varint".to_string(),
    };
    let debug = format!("{event:?}");
    assert!(debug.contains("ParseError"));
    assert!(debug.contains("bad varint"));
}

#[test]
fn proxy_event_session_ended() {
    let event =
        ProxyEvent::SessionEnded { session_id: SessionId(1), reason: "completed".to_string() };
    let debug = format!("{event:?}");
    assert!(debug.contains("SessionEnded"));
}

#[test]
fn proxy_event_clone() {
    let event = ProxyEvent::SessionEnded { session_id: SessionId(42), reason: "test".to_string() };
    let cloned = event.clone();
    assert!(format!("{cloned:?}").contains("42"));
}

// ============================================================
// NoOpProxyObserver
// ============================================================

#[test]
fn noop_observer_does_not_panic() {
    let obs = NoOpProxyObserver;
    let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    obs.on_event(&ProxyEvent::SessionStarted {
        session_id: SessionId(1),
        client_addr: addr,
        client_transport: "QUIC".into(),
    });
    obs.on_event(&ProxyEvent::SessionEnded {
        session_id: SessionId(1),
        reason: "done".to_string(),
    });
}

// ============================================================
// Custom observer collects events
// ============================================================

#[derive(Clone)]
struct CollectingObserver {
    events: Arc<Mutex<Vec<String>>>,
}

impl ProxyObserver for CollectingObserver {
    fn on_event(&self, event: &ProxyEvent) {
        let label = match event {
            ProxyEvent::SessionStarted { .. } => "SessionStarted",
            ProxyEvent::SetupMessage { .. } => "SetupMessage",
            ProxyEvent::ControlMessage { .. } => "ControlMessage",
            ProxyEvent::DataStreamHeader { .. } => "DataStreamHeader",
            ProxyEvent::ObjectHeader { .. } => "ObjectHeader",
            ProxyEvent::Datagram { .. } => "Datagram",
            ProxyEvent::BiStreamOpened { .. } => "BiStreamOpened",
            ProxyEvent::UniStreamOpened { .. } => "UniStreamOpened",
            ProxyEvent::ParseError { .. } => "ParseError",
            ProxyEvent::StreamClosed { .. } => "StreamClosed",
            ProxyEvent::SessionEnded { .. } => "SessionEnded",
        };
        self.events.lock().unwrap().push(label.to_string());
    }
}

#[test]
fn collecting_observer_receives_events() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let obs = CollectingObserver { events: events.clone() };
    let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

    obs.on_event(&ProxyEvent::SessionStarted {
        session_id: SessionId(1),
        client_addr: addr,
        client_transport: "QUIC".into(),
    });
    obs.on_event(&ProxyEvent::SessionEnded {
        session_id: SessionId(1),
        reason: "done".to_string(),
    });

    let collected = events.lock().unwrap();
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0], "SessionStarted");
    assert_eq!(collected[1], "SessionEnded");
}

/// Verify ProxyObserver is object-safe.
#[test]
fn observer_is_object_safe() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let obs: Box<dyn ProxyObserver> = Box::new(CollectingObserver { events: events.clone() });
    let addr: SocketAddr = "127.0.0.1:5678".parse().unwrap();
    obs.on_event(&ProxyEvent::SessionStarted {
        session_id: SessionId(99),
        client_addr: addr,
        client_transport: "QUIC".into(),
    });
    assert_eq!(events.lock().unwrap().len(), 1);
}

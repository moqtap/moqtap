use std::sync::{Arc, Mutex};

use moqtap_client::event::*;
use moqtap_client::observer::*;

// ============================================================
// Direction
// ============================================================

#[test]
fn direction_copy_and_eq() {
    let d = Direction::Send;
    let d2 = d;
    assert_eq!(d, d2);
    assert_ne!(Direction::Send, Direction::Receive);
}

#[test]
fn direction_debug() {
    assert_eq!(format!("{:?}", Direction::Send), "Send");
    assert_eq!(format!("{:?}", Direction::Receive), "Receive");
}

// ============================================================
// StreamKind
// ============================================================

#[test]
fn stream_kind_copy_and_eq() {
    let k = StreamKind::Subgroup;
    let k2 = k;
    assert_eq!(k, k2);
    assert_ne!(StreamKind::Subgroup, StreamKind::Fetch);
    assert_ne!(StreamKind::Fetch, StreamKind::Datagram);
}

// ============================================================
// ClientEvent construction
// ============================================================

#[test]
fn client_event_setup_complete() {
    let event = ClientEvent::SetupComplete { negotiated_version: 0xff00000e };
    let debug = format!("{event:?}");
    assert!(debug.contains("SetupComplete"));
}

#[test]
fn client_event_draining() {
    let event = ClientEvent::Draining { new_session_uri: b"https://new.example".to_vec() };
    let debug = format!("{event:?}");
    assert!(debug.contains("Draining"));
}

#[test]
fn client_event_closed() {
    let event = ClientEvent::Closed { code: 0, reason: b"normal".to_vec() };
    let debug = format!("{event:?}");
    assert!(debug.contains("Closed"));
}

#[test]
fn client_event_error() {
    let event = ClientEvent::Error { error: "something broke".to_string() };
    let debug = format!("{event:?}");
    assert!(debug.contains("Error"));
}

#[test]
fn client_event_stream_opened() {
    let event =
        ClientEvent::StreamOpened { direction: Direction::Send, stream_kind: StreamKind::Subgroup };
    let debug = format!("{event:?}");
    assert!(debug.contains("StreamOpened"));
}

#[test]
fn client_event_stream_closed() {
    let event = ClientEvent::StreamClosed { error_code: 0 };
    let debug = format!("{event:?}");
    assert!(debug.contains("StreamClosed"));
}

// ============================================================
// NoOpObserver
// ============================================================

#[test]
fn noop_observer_does_not_panic() {
    let obs = NoOpObserver;
    obs.on_event(&ClientEvent::SetupComplete { negotiated_version: 14 });
    obs.on_event(&ClientEvent::Error { error: "test".to_string() });
}

// ============================================================
// Custom observer collects events
// ============================================================

#[derive(Clone)]
struct CollectingObserver {
    events: Arc<Mutex<Vec<String>>>,
}

impl ConnectionObserver for CollectingObserver {
    fn on_event(&self, event: &ClientEvent) {
        let label = match event {
            ClientEvent::SetupComplete { .. } => "SetupComplete",
            ClientEvent::ControlMessage { .. } => "ControlMessage",
            ClientEvent::StreamOpened { .. } => "StreamOpened",
            ClientEvent::StreamClosed { .. } => "StreamClosed",
            ClientEvent::Draining { .. } => "Draining",
            ClientEvent::Closed { .. } => "Closed",
            ClientEvent::Error { .. } => "Error",
        };
        self.events.lock().unwrap().push(label.to_string());
    }
}

#[test]
fn collecting_observer_receives_events() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let obs = CollectingObserver { events: events.clone() };

    obs.on_event(&ClientEvent::SetupComplete { negotiated_version: 14 });
    obs.on_event(&ClientEvent::Error { error: "oops".to_string() });
    obs.on_event(&ClientEvent::Closed { code: 0, reason: vec![] });

    let collected = events.lock().unwrap();
    assert_eq!(collected.len(), 3);
    assert_eq!(collected[0], "SetupComplete");
    assert_eq!(collected[1], "Error");
    assert_eq!(collected[2], "Closed");
}

/// Verify ConnectionObserver is object-safe (can be used as Box<dyn>).
#[test]
fn observer_is_object_safe() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let obs: Box<dyn ConnectionObserver> = Box::new(CollectingObserver { events: events.clone() });
    obs.on_event(&ClientEvent::SetupComplete { negotiated_version: 14 });
    assert_eq!(events.lock().unwrap().len(), 1);
}

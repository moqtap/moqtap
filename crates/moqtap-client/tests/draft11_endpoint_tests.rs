#![cfg(feature = "draft11")]

use moqtap_client::draft11::endpoint::*;
use moqtap_client::draft11::session::state::SessionState;
use moqtap_codec::draft11::message::{self, *};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

fn ns(parts: &[&[u8]]) -> TrackNamespace {
    TrackNamespace(parts.iter().map(|p| p.to_vec()).collect())
}

/// group_order = Original (0) as a VarInt.
fn group_order_original() -> VarInt {
    varint(0)
}

/// filter_type = LargestObject (2) as a VarInt.
fn filter_largest_object() -> VarInt {
    varint(2)
}

// ============================================================
// Construction and initial state
// ============================================================

#[test]
fn endpoint_starts_in_connecting() {
    let ep = Endpoint::new();
    assert_eq!(ep.session_state(), SessionState::Connecting);
    assert_eq!(ep.active_subscription_count(), 0);
    assert_eq!(ep.active_fetch_count(), 0);
    assert_eq!(ep.active_subscribe_announces_count(), 0);
    assert_eq!(ep.active_announce_count(), 0);
    assert_eq!(ep.active_track_status_count(), 0);
}

// ============================================================
// Session lifecycle
// ============================================================

fn make_active_client() -> Endpoint {
    let mut ep = Endpoint::new();
    ep.connect().unwrap();
    let versions = vec![varint(0xff00000b)];
    let _ = ep.send_client_setup(versions, vec![]).unwrap();
    let server_setup = ServerSetup {
        selected_version: varint(0xff00000b),
        parameters: vec![KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(100)) }],
    };
    ep.receive_server_setup(&server_setup).unwrap();
    ep
}

#[test]
fn endpoint_connect_transitions_to_setup_exchange() {
    let mut ep = Endpoint::new();
    ep.connect().unwrap();
    assert_eq!(ep.session_state(), SessionState::SetupExchange);
}

#[test]
fn endpoint_receive_server_setup_activates_session() {
    let ep = make_active_client();
    assert_eq!(ep.session_state(), SessionState::Active);
    assert_eq!(ep.negotiated_version(), Some(varint(0xff00000b)));
    assert!(!ep.is_blocked());
}

#[test]
fn endpoint_blocked_without_max_request_id() {
    let mut ep = Endpoint::new();
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff00000b)], vec![]).unwrap();
    let server_setup = ServerSetup { selected_version: varint(0xff00000b), parameters: vec![] };
    ep.receive_server_setup(&server_setup).unwrap();
    assert!(ep.is_blocked());
}

#[test]
fn endpoint_server_setup_wrong_version_fails() {
    let mut ep = Endpoint::new();
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff00000b)], vec![]).unwrap();
    let server_setup = ServerSetup { selected_version: varint(0xff000099), parameters: vec![] };
    assert!(ep.receive_server_setup(&server_setup).is_err());
}

// ============================================================
// Subscribe flow
// ============================================================

fn default_subscribe(ep: &mut Endpoint, track: &[u8]) -> (VarInt, ControlMessage) {
    ep.subscribe(
        varint(1),
        ns(&[b"ns"]),
        track.to_vec(),
        0,
        group_order_original(),
        filter_largest_object(),
    )
    .unwrap()
}

#[test]
fn endpoint_subscribe_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = default_subscribe(&mut ep, b"trk");
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_subscription_count(), 1);
    assert!(matches!(msg, ControlMessage::Subscribe(_)));
}

fn subscribe_ok_for(id: VarInt) -> ControlMessage {
    ControlMessage::SubscribeOk(SubscribeOk {
        request_id: id,
        expires: varint(0),
        group_order: group_order_original(),
        content_exists: varint(0),
        largest_location: None,
        parameters: vec![],
    })
}

#[test]
fn endpoint_subscribe_ok_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id)).unwrap();
}

#[test]
fn endpoint_subscribe_done_ends_subscription_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id)).unwrap();

    let done = ControlMessage::SubscribeDone(SubscribeDone {
        request_id: id,
        status_code: varint(0),
        stream_count: varint(0),
        reason_phrase: vec![],
    });
    ep.receive_message(done).unwrap();
}

#[test]
fn endpoint_unsubscribe_produces_message() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id)).unwrap();
    let msg = ep.unsubscribe(id).unwrap();
    assert!(matches!(msg, ControlMessage::Unsubscribe(_)));
}

#[test]
fn endpoint_monotonic_request_ids() {
    let mut ep = make_active_client();
    let (id0, _) = default_subscribe(&mut ep, b"a");
    let (id1, _) = default_subscribe(&mut ep, b"b");
    let (id2, _) = default_subscribe(&mut ep, b"c");
    assert_eq!(id0.into_inner(), 0);
    assert_eq!(id1.into_inner(), 1);
    assert_eq!(id2.into_inner(), 2);
}

// ============================================================
// Fetch flow
// ============================================================

fn default_fetch(ep: &mut Endpoint) -> (VarInt, ControlMessage) {
    ep.fetch(
        ns(&[b"ns"]),
        b"trk".to_vec(),
        0,
        group_order_original(),
        varint(0),
        varint(0),
        varint(10),
        varint(0),
    )
    .unwrap()
}

#[test]
fn endpoint_fetch_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = default_fetch(&mut ep);
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_fetch_count(), 1);
    match &msg {
        ControlMessage::Fetch(f) => {
            assert_eq!(f.fetch_type as u64, FetchType::Standalone as u64);
            match &f.fetch_payload {
                FetchPayload::Standalone { track_namespace, track_name, .. } => {
                    assert_eq!(track_namespace.0, vec![b"ns".to_vec()]);
                    assert_eq!(track_name, b"trk");
                }
                _ => panic!("expected Standalone payload"),
            }
        }
        _ => panic!("expected Fetch control message"),
    }
}

#[test]
fn endpoint_fetch_ok_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let ok = ControlMessage::FetchOk(message::FetchOk {
        request_id: id,
        group_order: group_order_original(),
        end_of_track: varint(0),
        end_location: Location { group: varint(10), object: varint(0) },
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_fetch_cancel_produces_message() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let msg = ep.fetch_cancel(id).unwrap();
    assert!(matches!(msg, ControlMessage::FetchCancel(_)));
}

// ============================================================
// Announce flow
// ============================================================

#[test]
fn endpoint_announce_tracks_namespace() {
    let mut ep = make_active_client();
    let (_id, msg) = ep.announce(ns(&[b"pub", b"alice"])).unwrap();
    assert_eq!(ep.active_announce_count(), 1);
    assert!(matches!(msg, ControlMessage::Announce(_)));
}

#[test]
fn endpoint_announce_ok_via_dispatch() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.announce(ns(&[b"pub", b"alice"])).unwrap();
    let ok = ControlMessage::AnnounceOk(AnnounceOk { request_id: req_id });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_unannounce_after_ok() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.announce(ns(&[b"pub", b"alice"])).unwrap();
    let ok = ControlMessage::AnnounceOk(AnnounceOk { request_id: req_id });
    ep.receive_message(ok).unwrap();
    let msg = ep.unannounce(ns(&[b"pub", b"alice"])).unwrap();
    assert!(matches!(msg, ControlMessage::Unannounce(_)));
}

#[test]
fn endpoint_unknown_announce_request_id_rejected() {
    let mut ep = make_active_client();
    let ok = ControlMessage::AnnounceOk(AnnounceOk { request_id: varint(999) });
    assert!(ep.receive_message(ok).is_err());
}

// ============================================================
// SubscribeAnnounces flow
// ============================================================

#[test]
fn endpoint_subscribe_announces_roundtrip() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.subscribe_announces(ns(&[b"prefix"])).unwrap();
    assert_eq!(ep.active_subscribe_announces_count(), 1);
    let ok = ControlMessage::SubscribeAnnouncesOk(SubscribeAnnouncesOk { request_id: req_id });
    ep.receive_message(ok).unwrap();
    let msg = ep.unsubscribe_announces(ns(&[b"prefix"])).unwrap();
    assert!(matches!(msg, ControlMessage::UnsubscribeAnnounces(_)));
}

// ============================================================
// Track status flow
// ============================================================

#[test]
fn endpoint_track_status_request_and_reply() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.track_status_request(ns(&[b"ns"]), b"trk".to_vec()).unwrap();
    assert_eq!(ep.active_track_status_count(), 1);
    let reply = ControlMessage::TrackStatus(TrackStatus {
        request_id: req_id,
        status_code: varint(0),
        largest_location: Location { group: varint(5), object: varint(7) },
        parameters: vec![],
    });
    ep.receive_message(reply).unwrap();
}

#[test]
fn endpoint_unknown_track_status_rejected() {
    let mut ep = make_active_client();
    let reply = ControlMessage::TrackStatus(TrackStatus {
        request_id: varint(999),
        status_code: varint(0),
        largest_location: Location { group: varint(0), object: varint(0) },
        parameters: vec![],
    });
    assert!(ep.receive_message(reply).is_err());
}

// ============================================================
// GoAway
// ============================================================

#[test]
fn endpoint_goaway_transitions_to_draining() {
    let mut ep = make_active_client();
    let msg = GoAway { new_session_uri: b"https://new".to_vec() };
    ep.receive_goaway(&msg).unwrap();
    assert_eq!(ep.session_state(), SessionState::Draining);
    assert_eq!(ep.goaway_uri(), Some(b"https://new".as_slice()));
}

#[test]
fn endpoint_draining_rejects_new_subscribe() {
    let mut ep = make_active_client();
    ep.receive_goaway(&GoAway { new_session_uri: vec![] }).unwrap();
    let result = ep.subscribe(
        varint(1),
        ns(&[b"ns"]),
        b"trk".to_vec(),
        0,
        group_order_original(),
        filter_largest_object(),
    );
    assert!(matches!(result, Err(EndpointError::Draining)));
}

// ============================================================
// MAX_REQUEST_ID
// ============================================================

#[test]
fn endpoint_max_request_id_monotonic_send() {
    let mut ep = make_active_client();
    let _ = ep.send_max_request_id(varint(200)).unwrap();
    let _ = ep.send_max_request_id(varint(300)).unwrap();
    assert!(ep.send_max_request_id(varint(200)).is_err());
}

#[test]
fn endpoint_receive_max_request_id_raises_limit() {
    let mut ep = make_active_client();
    ep.receive_max_request_id(&MaxRequestId { request_id: varint(1000) }).unwrap();
    assert!(!ep.is_blocked());
}

// ============================================================
// REQUESTS_BLOCKED
// ============================================================

#[test]
fn endpoint_receive_requests_blocked_records_peer_max() {
    let mut ep = make_active_client();
    let msg = ControlMessage::RequestsBlocked(RequestsBlocked { maximum_request_id: varint(100) });
    ep.receive_message(msg).unwrap();
    assert_eq!(ep.peer_reported_max_request_id(), Some(varint(100)));
}

// ============================================================
// Joining fetch
// ============================================================

#[test]
fn endpoint_joining_fetch_allocates_and_tracks() {
    let mut ep = make_active_client();
    // Open a parent subscription first
    let (parent_id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(parent_id)).unwrap();

    // Issue a joining fetch against it
    let (fetch_id, msg) = ep
        .joining_fetch(0, group_order_original(), FetchType::RelativeJoining, parent_id, varint(2))
        .unwrap();
    assert_ne!(fetch_id.into_inner(), parent_id.into_inner());
    assert_eq!(ep.active_fetch_count(), 1);
    match msg {
        ControlMessage::Fetch(ref f) => {
            assert_eq!(f.fetch_type as u64, FetchType::RelativeJoining as u64);
            match &f.fetch_payload {
                FetchPayload::Joining { joining_subscribe_id, joining_start } => {
                    assert_eq!(*joining_subscribe_id, parent_id);
                    assert_eq!(*joining_start, varint(2));
                }
                _ => panic!("expected Joining payload"),
            }
        }
        _ => panic!("expected Fetch control message"),
    }
}

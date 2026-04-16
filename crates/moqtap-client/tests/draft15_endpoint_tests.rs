#![cfg(feature = "draft15")]

use moqtap_client::draft15::endpoint::*;
use moqtap_client::draft15::session::request_id::Role;
use moqtap_client::draft15::session::state::SessionState;
use moqtap_codec::draft15::message::*;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

fn ns(parts: &[&[u8]]) -> TrackNamespace {
    TrackNamespace(parts.iter().map(|p| p.to_vec()).collect())
}

// ============================================================
// Construction and initial state
// ============================================================

#[test]
fn endpoint_starts_in_connecting() {
    let ep = Endpoint::new(Role::Client);
    assert_eq!(ep.role(), Role::Client);
    assert_eq!(ep.session_state(), SessionState::Connecting);
    assert_eq!(ep.active_subscription_count(), 0);
    assert_eq!(ep.active_fetch_count(), 0);
    assert_eq!(ep.active_subscribe_namespace_count(), 0);
    assert_eq!(ep.active_publish_namespace_count(), 0);
    assert_eq!(ep.active_track_status_count(), 0);
    assert_eq!(ep.active_publish_count(), 0);
}

#[test]
fn endpoint_server_role() {
    let ep = Endpoint::new(Role::Server);
    assert_eq!(ep.role(), Role::Server);
}

// ============================================================
// Session lifecycle (draft-15: ALPN-based, no versions)
// ============================================================

fn make_active_client() -> Endpoint {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![]).unwrap();
    let server_setup = ServerSetup {
        parameters: vec![KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(100)) }],
    };
    ep.receive_server_setup(&server_setup).unwrap();
    ep
}

fn make_active_server() -> Endpoint {
    let mut ep = Endpoint::new(Role::Server);
    ep.connect().unwrap();
    let client_setup = ClientSetup { parameters: vec![] };
    let _ = ep.receive_client_setup_and_respond(&client_setup).unwrap();
    ep
}

#[test]
fn endpoint_connect_transitions_to_setup_exchange() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    assert_eq!(ep.session_state(), SessionState::SetupExchange);
}

#[test]
fn endpoint_receive_server_setup_activates_session() {
    let ep = make_active_client();
    assert_eq!(ep.session_state(), SessionState::Active);
    assert!(!ep.is_blocked());
}

#[test]
fn endpoint_server_setup_activates_session() {
    let ep = make_active_server();
    assert_eq!(ep.session_state(), SessionState::Active);
}

#[test]
fn endpoint_blocked_without_max_request_id() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![]).unwrap();
    let server_setup = ServerSetup { parameters: vec![] };
    ep.receive_server_setup(&server_setup).unwrap();
    assert!(ep.is_blocked());
}

// ============================================================
// Subscribe flow (draft-15: simplified, no group_order/filter_type)
// ============================================================

fn default_subscribe(ep: &mut Endpoint, track: &[u8]) -> (VarInt, ControlMessage) {
    ep.subscribe(ns(&[b"ns"]), track.to_vec(), vec![]).unwrap()
}

#[test]
fn endpoint_subscribe_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = default_subscribe(&mut ep, b"trk");
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_subscription_count(), 1);
    match &msg {
        ControlMessage::Subscribe(s) => {
            assert_eq!(s.request_id, id);
            assert_eq!(s.track_namespace.0, vec![b"ns".to_vec()]);
            assert_eq!(s.track_name, b"trk");
        }
        _ => panic!("expected Subscribe"),
    }
}

fn subscribe_ok_for(id: VarInt, alias: VarInt) -> ControlMessage {
    ControlMessage::SubscribeOk(SubscribeOk {
        request_id: id,
        track_alias: alias,
        parameters: vec![],
    })
}

#[test]
fn endpoint_subscribe_ok_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id, varint(42))).unwrap();
}

#[test]
fn endpoint_subscribe_error_via_request_error() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    let err = ControlMessage::RequestError(RequestError {
        request_id: id,
        error_code: varint(1),
        reason_phrase: b"nope".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

#[test]
fn endpoint_subscribe_update_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id, varint(1))).unwrap();
    // SubscribeUpdate uses subscription_request_id to reference the original
    let upd = ControlMessage::SubscribeUpdate(SubscribeUpdate {
        request_id: varint(99), // new request ID for the update itself
        subscription_request_id: id,
        parameters: vec![],
    });
    ep.receive_message(upd).unwrap();
}

#[test]
fn endpoint_unsubscribe_produces_message() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id, varint(1))).unwrap();
    let msg = ep.unsubscribe(id).unwrap();
    assert!(matches!(msg, ControlMessage::Unsubscribe(_)));
}

#[test]
fn endpoint_receive_publish_done_ends_subscription() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(id, varint(1))).unwrap();
    let done = ControlMessage::PublishDone(PublishDone {
        request_id: id,
        status_code: varint(0),
        stream_count: varint(0),
        reason_phrase: vec![],
    });
    ep.receive_message(done).unwrap();
}

#[test]
fn endpoint_client_even_request_ids() {
    let mut ep = make_active_client();
    let (id0, _) = default_subscribe(&mut ep, b"a");
    let (id1, _) = default_subscribe(&mut ep, b"b");
    let (id2, _) = default_subscribe(&mut ep, b"c");
    assert_eq!(id0.into_inner(), 0);
    assert_eq!(id1.into_inner(), 2);
    assert_eq!(id2.into_inner(), 4);
}

// ============================================================
// Fetch flow (draft-15: FetchType/FetchPayload with end_object)
// ============================================================

fn default_fetch(ep: &mut Endpoint) -> (VarInt, ControlMessage) {
    ep.fetch(ns(&[b"ns"]), b"trk".to_vec(), varint(0), varint(0), varint(10), varint(0)).unwrap()
}

#[test]
fn endpoint_fetch_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = default_fetch(&mut ep);
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_fetch_count(), 1);
    match &msg {
        ControlMessage::Fetch(f) => {
            assert_eq!(f.request_id, id);
            assert_eq!(f.fetch_type as u64, FetchType::Standalone as u64);
            match &f.fetch_payload {
                FetchPayload::Standalone { track_namespace, track_name, .. } => {
                    assert_eq!(track_namespace.0, vec![b"ns".to_vec()]);
                    assert_eq!(track_name, b"trk");
                }
                _ => panic!("expected Standalone payload"),
            }
        }
        _ => panic!("expected Fetch"),
    }
}

#[test]
fn endpoint_fetch_ok_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let ok = ControlMessage::FetchOk(FetchOk {
        request_id: id,
        end_of_track: varint(0),
        end_group: varint(10),
        end_object: varint(0),
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_fetch_error_via_request_error() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let err = ControlMessage::RequestError(RequestError {
        request_id: id,
        error_code: varint(1),
        reason_phrase: b"not found".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

#[test]
fn endpoint_fetch_cancel_produces_message() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let msg = ep.fetch_cancel(id).unwrap();
    assert!(matches!(msg, ControlMessage::FetchCancel(_)));
}

#[test]
fn endpoint_fetch_stream_fin() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let ok = ControlMessage::FetchOk(FetchOk {
        request_id: id,
        end_of_track: varint(0),
        end_group: varint(10),
        end_object: varint(0),
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
    ep.on_fetch_stream_fin(id).unwrap();
}

// ============================================================
// Joining Fetch
// ============================================================

#[test]
fn endpoint_joining_fetch_allocates_and_tracks() {
    let mut ep = make_active_client();
    // Open a parent subscription first
    let (parent_id, _) = default_subscribe(&mut ep, b"trk");
    ep.receive_message(subscribe_ok_for(parent_id, varint(1))).unwrap();

    let (fetch_id, msg) = ep.joining_fetch(parent_id, varint(2)).unwrap();
    assert_ne!(fetch_id.into_inner(), parent_id.into_inner());
    assert_eq!(ep.active_fetch_count(), 1);
    match msg {
        ControlMessage::Fetch(ref f) => {
            assert_eq!(f.fetch_type as u64, FetchType::RelativeJoining as u64);
            match &f.fetch_payload {
                FetchPayload::Joining { joining_request_id, joining_start } => {
                    assert_eq!(*joining_request_id, parent_id);
                    assert_eq!(*joining_start, varint(2));
                }
                _ => panic!("expected Joining payload"),
            }
        }
        _ => panic!("expected Fetch control message"),
    }
}

// ============================================================
// Publish flow (publisher side)
// ============================================================

#[test]
fn endpoint_publish_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) =
        ep.publish(ns(&[b"pub", b"alice"]), b"trk".to_vec(), varint(42), vec![]).unwrap();
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_publish_count(), 1);
    match &msg {
        ControlMessage::Publish(p) => {
            assert_eq!(p.request_id, id);
            assert_eq!(p.track_namespace.0, vec![b"pub".to_vec(), b"alice".to_vec()]);
            assert_eq!(p.track_name, b"trk");
            assert_eq!(p.track_alias, varint(42));
        }
        _ => panic!("expected Publish"),
    }
}

#[test]
fn endpoint_publish_ok_activates_publish() {
    let mut ep = make_active_client();
    let (id, _) = ep.publish(ns(&[b"pub"]), b"trk".to_vec(), varint(1), vec![]).unwrap();
    let ok = PublishOk { request_id: id, parameters: vec![] };
    ep.receive_publish_ok(&ok).unwrap();
}

#[test]
fn endpoint_publish_done_lifecycle() {
    let mut ep = make_active_client();
    let (id, _) = ep.publish(ns(&[b"pub"]), b"trk".to_vec(), varint(1), vec![]).unwrap();
    let ok = PublishOk { request_id: id, parameters: vec![] };
    ep.receive_publish_ok(&ok).unwrap();
    // Draft-15 PublishDone has stream_count
    let done = ep.send_publish_done(id, varint(0), varint(5), vec![]).unwrap();
    match &done {
        ControlMessage::PublishDone(d) => {
            assert_eq!(d.stream_count, varint(5));
        }
        _ => panic!("expected PublishDone"),
    }
}

#[test]
fn endpoint_publish_error_via_request_error() {
    let mut ep = make_active_client();
    let (id, _) = ep.publish(ns(&[b"pub"]), b"trk".to_vec(), varint(1), vec![]).unwrap();
    let err = ControlMessage::RequestError(RequestError {
        request_id: id,
        error_code: varint(3),
        reason_phrase: b"denied".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

// ============================================================
// Publish Namespace flow
// ============================================================

#[test]
fn endpoint_publish_namespace_roundtrip() {
    let mut ep = make_active_client();
    let (req_id, msg) = ep.publish_namespace(ns(&[b"pub", b"alice"]), vec![]).unwrap();
    assert_eq!(ep.active_publish_namespace_count(), 1);
    assert!(matches!(msg, ControlMessage::PublishNamespace(_)));

    // Ok via consolidated RequestOk
    let ok = ControlMessage::RequestOk(RequestOk { request_id: req_id, parameters: vec![] });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_publish_namespace_error_via_request_error() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.publish_namespace(ns(&[b"pub"]), vec![]).unwrap();
    let err = ControlMessage::RequestError(RequestError {
        request_id: req_id,
        error_code: varint(1),
        reason_phrase: b"denied".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

#[test]
fn endpoint_publish_namespace_done_by_namespace() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.publish_namespace(ns(&[b"pub"]), vec![]).unwrap();
    let ok = ControlMessage::RequestOk(RequestOk { request_id: req_id, parameters: vec![] });
    ep.receive_message(ok).unwrap();
    // PublishNamespaceDone uses track_namespace, not request_id
    let done = ControlMessage::PublishNamespaceDone(PublishNamespaceDone {
        track_namespace: ns(&[b"pub"]),
    });
    ep.receive_message(done).unwrap();
}

#[test]
fn endpoint_publish_namespace_cancel_by_namespace() {
    let mut ep = make_active_client();
    let (_req_id, _) = ep.publish_namespace(ns(&[b"pub"]), vec![]).unwrap();
    let ok = ControlMessage::RequestOk(RequestOk { request_id: _req_id, parameters: vec![] });
    ep.receive_message(ok).unwrap();
    // Cancel uses track_namespace
    let msg = ep.publish_namespace_cancel(ns(&[b"pub"]), varint(0), b"done".to_vec()).unwrap();
    assert!(matches!(msg, ControlMessage::PublishNamespaceCancel(_)));
}

#[test]
fn endpoint_unknown_publish_namespace_ok_rejected() {
    let mut ep = make_active_client();
    let ok = ControlMessage::RequestOk(RequestOk { request_id: varint(999), parameters: vec![] });
    assert!(ep.receive_message(ok).is_err());
}

// ============================================================
// Subscribe Namespace flow
// ============================================================

#[test]
fn endpoint_subscribe_namespace_roundtrip() {
    let mut ep = make_active_client();
    let (req_id, msg) = ep.subscribe_namespace(ns(&[b"prefix"]), vec![]).unwrap();
    assert_eq!(ep.active_subscribe_namespace_count(), 1);
    match &msg {
        ControlMessage::SubscribeNamespace(sn) => {
            assert_eq!(sn.namespace_prefix.0, vec![b"prefix".to_vec()]);
        }
        _ => panic!("expected SubscribeNamespace"),
    }

    // Ok via consolidated RequestOk
    let ok = ControlMessage::RequestOk(RequestOk { request_id: req_id, parameters: vec![] });
    ep.receive_message(ok).unwrap();

    let unsub = ep.unsubscribe_namespace(req_id).unwrap();
    assert!(matches!(unsub, ControlMessage::UnsubscribeNamespace(_)));
}

#[test]
fn endpoint_subscribe_namespace_error_via_request_error() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.subscribe_namespace(ns(&[b"prefix"]), vec![]).unwrap();
    let err = ControlMessage::RequestError(RequestError {
        request_id: req_id,
        error_code: varint(1),
        reason_phrase: b"denied".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

// ============================================================
// Track Status flow (draft-15: simplified with parameters)
// ============================================================

#[test]
fn endpoint_track_status_request_and_ok() {
    let mut ep = make_active_client();
    let (req_id, msg) = ep.track_status(ns(&[b"ns"]), b"trk".to_vec(), vec![]).unwrap();
    assert_eq!(ep.active_track_status_count(), 1);
    assert!(matches!(msg, ControlMessage::TrackStatus(_)));

    // Ok via consolidated RequestOk
    let reply = ControlMessage::RequestOk(RequestOk { request_id: req_id, parameters: vec![] });
    ep.receive_message(reply).unwrap();
}

#[test]
fn endpoint_track_status_error_via_request_error() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.track_status(ns(&[b"ns"]), b"trk".to_vec(), vec![]).unwrap();
    let reply = ControlMessage::RequestError(RequestError {
        request_id: req_id,
        error_code: varint(1),
        reason_phrase: b"not found".to_vec(),
    });
    ep.receive_message(reply).unwrap();
}

#[test]
fn endpoint_unknown_track_status_ok_rejected() {
    let mut ep = make_active_client();
    let reply =
        ControlMessage::RequestOk(RequestOk { request_id: varint(999), parameters: vec![] });
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
    let result = ep.subscribe(ns(&[b"ns"]), b"trk".to_vec(), vec![]);
    assert!(matches!(result, Err(EndpointError::Draining)));
}

#[test]
fn endpoint_draining_rejects_new_publish() {
    let mut ep = make_active_client();
    ep.receive_goaway(&GoAway { new_session_uri: vec![] }).unwrap();
    let result = ep.publish(ns(&[b"pub"]), b"trk".to_vec(), varint(1), vec![]);
    assert!(matches!(result, Err(EndpointError::Draining)));
}

#[test]
fn endpoint_draining_rejects_new_fetch() {
    let mut ep = make_active_client();
    ep.receive_goaway(&GoAway { new_session_uri: vec![] }).unwrap();
    let result =
        ep.fetch(ns(&[b"ns"]), b"trk".to_vec(), varint(0), varint(0), varint(10), varint(0));
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
fn endpoint_send_requests_blocked() {
    let ep = make_active_client();
    let msg = ep.send_requests_blocked().unwrap();
    assert!(matches!(msg, ControlMessage::RequestsBlocked(_)));
}

#[test]
fn endpoint_receive_requests_blocked() {
    let ep = make_active_client();
    let msg = RequestsBlocked { maximum_request_id: varint(100) };
    ep.receive_requests_blocked(&msg).unwrap();
}

// ============================================================
// Close
// ============================================================

#[test]
fn endpoint_close_from_active() {
    let mut ep = make_active_client();
    ep.close().unwrap();
    assert_eq!(ep.session_state(), SessionState::Closed);
}

#[test]
fn endpoint_close_from_draining() {
    let mut ep = make_active_client();
    ep.receive_goaway(&GoAway { new_session_uri: vec![] }).unwrap();
    ep.close().unwrap();
    assert_eq!(ep.session_state(), SessionState::Closed);
}

// ============================================================
// Mixed request ID allocation across flows
// ============================================================

#[test]
fn endpoint_mixed_flows_allocate_distinct_even_ids() {
    let mut ep = make_active_client();
    let (sub_id, _) = default_subscribe(&mut ep, b"trk");
    let (fetch_id, _) = default_fetch(&mut ep);
    let (pub_id, _) = ep.publish(ns(&[b"pub"]), b"trk".to_vec(), varint(1), vec![]).unwrap();
    let (ns_id, _) = ep.publish_namespace(ns(&[b"pub"]), vec![]).unwrap();
    let (ts_id, _) = ep.track_status(ns(&[b"ns"]), b"trk".to_vec(), vec![]).unwrap();

    // Client uses even IDs: 0, 2, 4, 6, 8
    assert_eq!(sub_id.into_inner(), 0);
    assert_eq!(fetch_id.into_inner(), 2);
    assert_eq!(pub_id.into_inner(), 4);
    assert_eq!(ns_id.into_inner(), 6);
    assert_eq!(ts_id.into_inner(), 8);
}

// ============================================================
// Consolidated RequestError routing
// ============================================================

#[test]
fn endpoint_request_error_routes_to_correct_state_machine() {
    let mut ep = make_active_client();
    let (sub_id, _) = default_subscribe(&mut ep, b"trk");
    let (fetch_id, _) = default_fetch(&mut ep);
    let (pub_id, _) = ep.publish(ns(&[b"pub"]), b"trk".to_vec(), varint(1), vec![]).unwrap();

    // Error routed to subscription
    let err = ControlMessage::RequestError(RequestError {
        request_id: sub_id,
        error_code: varint(1),
        reason_phrase: b"sub error".to_vec(),
    });
    ep.receive_message(err).unwrap();

    // Error routed to fetch
    let err = ControlMessage::RequestError(RequestError {
        request_id: fetch_id,
        error_code: varint(2),
        reason_phrase: b"fetch error".to_vec(),
    });
    ep.receive_message(err).unwrap();

    // Error routed to publish
    let err = ControlMessage::RequestError(RequestError {
        request_id: pub_id,
        error_code: varint(3),
        reason_phrase: b"pub error".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

#[test]
fn endpoint_request_error_unknown_id_ignored() {
    let mut ep = make_active_client();
    let err = ControlMessage::RequestError(RequestError {
        request_id: varint(999),
        error_code: varint(1),
        reason_phrase: b"unknown".to_vec(),
    });
    // Unknown request IDs are silently ignored per spec
    ep.receive_message(err).unwrap();
}

#![cfg(feature = "draft14")]

use moqtap_client::draft14::endpoint::*;
use moqtap_client::draft14::session::request_id::Role;
use moqtap_client::draft14::session::state::SessionState;
use moqtap_codec::draft14::message::{self, *};
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
// Session lifecycle
// ============================================================

fn make_active_client() -> Endpoint {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff00000e)], vec![]).unwrap();
    let server_setup = ServerSetup {
        selected_version: varint(0xff00000e),
        parameters: vec![KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(100)) }],
    };
    ep.receive_server_setup(&server_setup).unwrap();
    ep
}

fn make_active_server() -> Endpoint {
    let mut ep = Endpoint::new(Role::Server);
    ep.connect().unwrap();
    let client_setup =
        ClientSetup { supported_versions: vec![varint(0xff00000e)], parameters: vec![] };
    let _ = ep.receive_client_setup_and_respond(&client_setup, varint(0xff00000e)).unwrap();
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
    assert_eq!(ep.negotiated_version(), Some(varint(0xff00000e)));
    assert!(!ep.is_blocked());
}

#[test]
fn endpoint_server_setup_activates_session() {
    let ep = make_active_server();
    assert_eq!(ep.session_state(), SessionState::Active);
    assert_eq!(ep.negotiated_version(), Some(varint(0xff00000e)));
}

#[test]
fn endpoint_blocked_without_max_request_id() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff00000e)], vec![]).unwrap();
    let server_setup = ServerSetup { selected_version: varint(0xff00000e), parameters: vec![] };
    ep.receive_server_setup(&server_setup).unwrap();
    assert!(ep.is_blocked());
}

#[test]
fn endpoint_server_setup_wrong_version_fails() {
    let mut ep = Endpoint::new(Role::Client);
    ep.connect().unwrap();
    let _ = ep.send_client_setup(vec![varint(0xff00000e)], vec![]).unwrap();
    let server_setup = ServerSetup { selected_version: varint(0xff000099), parameters: vec![] };
    assert!(ep.receive_server_setup(&server_setup).is_err());
}

// ============================================================
// Subscribe flow
// ============================================================

fn default_subscribe(ep: &mut Endpoint, track: &[u8]) -> (VarInt, ControlMessage) {
    ep.subscribe(ns(&[b"ns"]), track.to_vec(), 0, GroupOrder::Publisher, FilterType::LargestObject)
        .unwrap()
}

#[test]
fn endpoint_subscribe_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = default_subscribe(&mut ep, b"trk");
    // Client uses even IDs, starts at 0
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_subscription_count(), 1);
    match &msg {
        ControlMessage::Subscribe(s) => {
            assert_eq!(s.request_id, id);
            assert_eq!(s.track_namespace.0, vec![b"ns".to_vec()]);
            assert_eq!(s.track_name, b"trk");
            assert_eq!(s.group_order, GroupOrder::Publisher);
            assert_eq!(s.filter_type, FilterType::LargestObject);
            assert_eq!(s.forward, Forward::Forward);
        }
        _ => panic!("expected Subscribe"),
    }
}

fn subscribe_ok_for(id: VarInt, alias: VarInt) -> ControlMessage {
    ControlMessage::SubscribeOk(SubscribeOk {
        request_id: id,
        track_alias: alias,
        expires: varint(0),
        group_order: GroupOrder::Publisher,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
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
fn endpoint_subscribe_error_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_subscribe(&mut ep, b"trk");
    let err = ControlMessage::SubscribeError(SubscribeError {
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
    let upd = ControlMessage::SubscribeUpdate(SubscribeUpdate {
        request_id: varint(999),
        subscription_request_id: id,
        start_location: Location { group: varint(0), object: varint(0) },
        end_group: varint(10),
        subscriber_priority: 5,
        forward: Forward::Forward,
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
// Fetch flow (simplified in draft-14)
// ============================================================

fn default_fetch(ep: &mut Endpoint) -> (VarInt, ControlMessage) {
    ep.fetch(ns(&[b"ns"]), b"trk".to_vec(), varint(0), varint(0)).unwrap()
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
            match &f.fetch_payload {
                message::FetchPayload::Standalone {
                    track_namespace,
                    track_name,
                    start_group,
                    start_object,
                    ..
                } => {
                    assert_eq!(track_namespace.0, vec![b"ns".to_vec()]);
                    assert_eq!(track_name, &b"trk".to_vec());
                    assert_eq!(*start_group, varint(0));
                    assert_eq!(*start_object, varint(0));
                }
                _ => panic!("expected standalone fetch payload"),
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
        group_order: GroupOrder::Ascending,
        end_of_track: varint(0),
        end_location: Location { group: varint(0), object: varint(0) },
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_fetch_error_via_dispatch() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let err = ControlMessage::FetchError(message::FetchError {
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
        group_order: GroupOrder::Ascending,
        end_of_track: varint(0),
        end_location: Location { group: varint(0), object: varint(0) },
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
    ep.on_fetch_stream_fin(id).unwrap();
}

#[test]
fn endpoint_fetch_stream_reset() {
    let mut ep = make_active_client();
    let (id, _) = default_fetch(&mut ep);
    let ok = ControlMessage::FetchOk(FetchOk {
        request_id: id,
        group_order: GroupOrder::Ascending,
        end_of_track: varint(0),
        end_location: Location { group: varint(0), object: varint(0) },
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
    ep.on_fetch_stream_reset(id).unwrap();
}

// ============================================================
// Publish flow (publisher side — new in draft-14)
// ============================================================

#[test]
fn endpoint_publish_allocates_and_tracks() {
    let mut ep = make_active_client();
    let (id, msg) = ep.publish(ns(&[b"pub", b"alice"]), b"trk".to_vec(), Forward::Forward).unwrap();
    assert_eq!(id.into_inner(), 0);
    assert_eq!(ep.active_publish_count(), 1);
    match &msg {
        ControlMessage::Publish(p) => {
            assert_eq!(p.request_id, id);
            assert_eq!(p.track_namespace.0, vec![b"pub".to_vec(), b"alice".to_vec()]);
            assert_eq!(p.track_name, b"trk");
            assert_eq!(p.forward, Forward::Forward);
        }
        _ => panic!("expected Publish"),
    }
}

#[test]
fn endpoint_publish_ok_activates_publish() {
    let mut ep = make_active_client();
    let (id, _) = ep.publish(ns(&[b"pub"]), b"trk".to_vec(), Forward::Forward).unwrap();
    let ok = PublishOk {
        request_id: id,
        forward: Forward::Forward,
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: None,
        parameters: vec![],
    };
    ep.receive_publish_ok(&ok).unwrap();
}

#[test]
fn endpoint_publish_done_lifecycle() {
    let mut ep = make_active_client();
    let (id, _) = ep.publish(ns(&[b"pub"]), b"trk".to_vec(), Forward::Forward).unwrap();
    let ok = PublishOk {
        request_id: id,
        forward: Forward::Forward,
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: None,
        parameters: vec![],
    };
    ep.receive_publish_ok(&ok).unwrap();
    let done = ep.send_publish_done(id, varint(0), vec![]).unwrap();
    assert!(matches!(done, ControlMessage::PublishDone(_)));
}

#[test]
fn endpoint_send_publish_error() {
    let ep = make_active_client();
    let resp = ep.send_publish_error(varint(7), varint(3), b"denied".to_vec()).unwrap();
    match &resp {
        ControlMessage::PublishError(e) => {
            assert_eq!(e.error_code, varint(3));
            assert_eq!(e.reason_phrase, b"denied");
        }
        _ => panic!("expected PublishError"),
    }
}

#[test]
fn endpoint_receive_publish_error_on_publish() {
    let mut ep = make_active_client();
    let (id, _) = ep.publish(ns(&[b"pub"]), b"trk".to_vec(), Forward::Forward).unwrap();
    let err = message::PublishError {
        request_id: id,
        error_code: varint(1),
        reason_phrase: b"rejected".to_vec(),
    };
    ep.receive_publish_error(&err).unwrap();
}

// ============================================================
// Publish Namespace flow (replaces Announce in draft-14)
// ============================================================

#[test]
fn endpoint_publish_namespace_roundtrip() {
    let mut ep = make_active_client();
    let (req_id, msg) = ep.publish_namespace(ns(&[b"pub", b"alice"])).unwrap();
    assert_eq!(ep.active_publish_namespace_count(), 1);
    assert!(matches!(msg, ControlMessage::PublishNamespace(_)));

    let ok = ControlMessage::PublishNamespaceOk(PublishNamespaceOk {
        request_id: req_id,
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
}

#[test]
fn endpoint_publish_namespace_error() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.publish_namespace(ns(&[b"pub"])).unwrap();
    let err = ControlMessage::PublishNamespaceError(PublishNamespaceError {
        request_id: req_id,
        error_code: varint(1),
        reason_phrase: b"denied".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

#[test]
fn endpoint_publish_namespace_done() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.publish_namespace(ns(&[b"pub"])).unwrap();
    let ok = ControlMessage::PublishNamespaceOk(PublishNamespaceOk {
        request_id: req_id,
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
    let done = ControlMessage::PublishNamespaceDone(PublishNamespaceDone {
        track_namespace: ns(&[b"pub"]),
    });
    let _ = req_id;
    ep.receive_message(done).unwrap();
}

#[test]
fn endpoint_publish_namespace_cancel() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.publish_namespace(ns(&[b"pub"])).unwrap();
    let ok = ControlMessage::PublishNamespaceOk(PublishNamespaceOk {
        request_id: req_id,
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();
    let msg = ep.publish_namespace_cancel(req_id, b"done".to_vec()).unwrap();
    assert!(matches!(msg, ControlMessage::PublishNamespaceCancel(_)));
}

#[test]
fn endpoint_unknown_publish_namespace_ok_rejected() {
    let mut ep = make_active_client();
    let ok = ControlMessage::PublishNamespaceOk(PublishNamespaceOk {
        request_id: varint(999),
        parameters: vec![],
    });
    assert!(ep.receive_message(ok).is_err());
}

// ============================================================
// Subscribe Namespace flow
// ============================================================

#[test]
fn endpoint_subscribe_namespace_roundtrip() {
    let mut ep = make_active_client();
    let (req_id, msg) = ep.subscribe_namespace(ns(&[b"prefix"])).unwrap();
    assert_eq!(ep.active_subscribe_namespace_count(), 1);
    assert!(matches!(msg, ControlMessage::SubscribeNamespace(_)));

    let ok = ControlMessage::SubscribeNamespaceOk(SubscribeNamespaceOk {
        request_id: req_id,
        parameters: vec![],
    });
    ep.receive_message(ok).unwrap();

    let unsub = ep.unsubscribe_namespace(req_id, ns(&[b"prefix"])).unwrap();
    assert!(matches!(unsub, ControlMessage::UnsubscribeNamespace(_)));
}

#[test]
fn endpoint_subscribe_namespace_error() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.subscribe_namespace(ns(&[b"prefix"])).unwrap();
    let err = ControlMessage::SubscribeNamespaceError(SubscribeNamespaceError {
        request_id: req_id,
        error_code: varint(1),
        reason_phrase: b"denied".to_vec(),
    });
    ep.receive_message(err).unwrap();
}

// ============================================================
// Track Status flow (simplified in draft-14)
// ============================================================

#[test]
fn endpoint_track_status_request_and_ok() {
    let mut ep = make_active_client();
    let (req_id, msg) = ep.track_status(ns(&[b"ns"]), b"trk".to_vec()).unwrap();
    assert_eq!(ep.active_track_status_count(), 1);
    assert!(matches!(msg, ControlMessage::TrackStatus(_)));

    let reply = ControlMessage::TrackStatusOk(TrackStatusOk {
        request_id: req_id,
        track_alias: varint(0),
        expires: varint(0),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![],
    });
    ep.receive_message(reply).unwrap();
}

#[test]
fn endpoint_track_status_error_reply() {
    let mut ep = make_active_client();
    let (req_id, _) = ep.track_status(ns(&[b"ns"]), b"trk".to_vec()).unwrap();
    let reply = ControlMessage::TrackStatusError(message::TrackStatusError {
        request_id: req_id,
        error_code: varint(1),
        reason_phrase: b"not found".to_vec(),
    });
    ep.receive_message(reply).unwrap();
}

#[test]
fn endpoint_unknown_track_status_ok_rejected() {
    let mut ep = make_active_client();
    let reply = ControlMessage::TrackStatusOk(TrackStatusOk {
        request_id: varint(999),
        track_alias: varint(0),
        expires: varint(0),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
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
        ns(&[b"ns"]),
        b"trk".to_vec(),
        0,
        GroupOrder::Publisher,
        FilterType::LargestObject,
    );
    assert!(matches!(result, Err(EndpointError::Draining)));
}

#[test]
fn endpoint_draining_rejects_new_publish() {
    let mut ep = make_active_client();
    ep.receive_goaway(&GoAway { new_session_uri: vec![] }).unwrap();
    let result = ep.publish(ns(&[b"pub"]), b"trk".to_vec(), Forward::Forward);
    assert!(matches!(result, Err(EndpointError::Draining)));
}

#[test]
fn endpoint_draining_rejects_new_fetch() {
    let mut ep = make_active_client();
    ep.receive_goaway(&GoAway { new_session_uri: vec![] }).unwrap();
    let result = ep.fetch(ns(&[b"ns"]), b"trk".to_vec(), varint(0), varint(0));
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
    let (pub_id, _) = ep.publish(ns(&[b"pub"]), b"trk".to_vec(), Forward::Forward).unwrap();
    let (ns_id, _) = ep.publish_namespace(ns(&[b"pub"])).unwrap();
    let (ts_id, _) = ep.track_status(ns(&[b"ns"]), b"trk".to_vec()).unwrap();

    // Client uses even IDs: 0, 2, 4, 6, 8
    assert_eq!(sub_id.into_inner(), 0);
    assert_eq!(fetch_id.into_inner(), 2);
    assert_eq!(pub_id.into_inner(), 4);
    assert_eq!(ns_id.into_inner(), 6);
    assert_eq!(ts_id.into_inner(), 8);
}
